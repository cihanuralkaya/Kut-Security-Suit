package grpc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	kutv1 "kut.corp/suite/gen/kut/v1"
	"kut.corp/suite/server/internal/model"
	"kut.corp/suite/server/internal/notify"
)

// peerCtx, verilen CN'e sahip doğrulanmış bir mTLS istemci kimliğini taşıyan bir
// context üretir (DeviceIDFromContext'in okuduğu güven sınırını taklit eder).
func peerCtx(cn string) context.Context {
	return peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: cn}}},
		}},
	})
}

// genSelfSigned, test için kendinden imzalı bir sertifika + anahtar PEM çifti
// üretir. Üretilen sertifika hem sunucu hem istemci-CA malzemesi olarak kullanılır.
func genSelfSigned(t *testing.T) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-tls"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM
}

// ---- In-test fakes for the AgentHandler collaborators ----

// fakeDevices, DeviceRegistry'nin yapılandırılabilir bir sahtesidir.
type fakeDevices struct {
	policyVer string
	touchErr  error

	pending []*kutv1.Command
	pendErr error

	tampered bool
	recErr   error
	recHash  string

	acked    []string
	outcomes []model.CommandOutcome
}

func (f *fakeDevices) TouchHeartbeat(_ context.Context, _, _, _ string, _ time.Time) (string, error) {
	return f.policyVer, f.touchErr
}
func (f *fakeDevices) PendingCommands(_ context.Context, _ string) ([]*kutv1.Command, error) {
	return f.pending, f.pendErr
}
func (f *fakeDevices) AckCommands(_ context.Context, _ string, ids []string) error {
	f.acked = ids
	return nil
}
func (f *fakeDevices) RecordAgentBinary(_ context.Context, _, _, hash string) (bool, error) {
	f.recHash = hash
	return f.tampered, f.recErr
}
func (f *fakeDevices) ApplyCommandResults(_ context.Context, _ string, outs []model.CommandOutcome) error {
	f.outcomes = outs
	return nil
}

// fakeEvents, EventSink'in sahtesidir; kaydedilen olayları biriktirir.
type fakeEvents struct {
	mu    sync.Mutex
	last  uint64
	err   error
	saved [][]model.Event
	calls int
}

func (f *fakeEvents) SaveEvents(_ context.Context, _ string, evs []model.Event) (uint64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.saved = append(f.saved, evs)
	if f.err != nil {
		return 0, f.err
	}
	return f.last, nil
}

// fakeUpdates, UpdateProvider'ın sahtesidir.
type fakeUpdates struct {
	m   *kutv1.UpdateManifest
	err error
}

func (f *fakeUpdates) LatestUpdate(_ context.Context, _, _, _ string) (*kutv1.UpdateManifest, error) {
	return f.m, f.err
}

// fakeResponder, AutoResponder'ın sahtesidir; çağrı sayısını tutar.
type fakeResponder struct {
	calls int
	err   error
}

func (f *fakeResponder) AutoQuarantine(context.Context, string, string) error {
	f.calls++
	return f.err
}

// fakeAdmin, AdminNotifier'ın sahtesidir; yayın sayaçlarını tutar.
type fakeAdmin struct {
	events  int
	devices int
}

func (f *fakeAdmin) PublishEvent(string, string, string) { f.events++ }
func (f *fakeAdmin) PublishDevice(string)                { f.devices++ }

// fakeAlerter, notify.Notifier'ın sahtesidir; gönderilen uyarıları toplar.
type fakeAlerter struct {
	mu     sync.Mutex
	alerts []notify.Alert
}

func (f *fakeAlerter) Notify(a notify.Alert) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.alerts = append(f.alerts, a)
}

func (f *fakeAlerter) all() []notify.Alert {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]notify.Alert, len(f.alerts))
	copy(out, f.alerts)
	return out
}

// fakeArtifacts, ArtifactSink'in sahtesidir.
type fakeArtifacts struct {
	saved   int
	err     error
	lastSHA string
}

func (f *fakeArtifacts) SaveArtifact(_ context.Context, _, _, _, sha string, _ []byte) (string, error) {
	f.saved++
	f.lastSHA = sha
	if f.err != nil {
		return "", f.err
	}
	return "artifact-id", nil
}

// fakeStream, AgentService_ReportEventsServer (ClientStreamingServer) sahtesidir.
// Sıralı batch'leri Recv'den döner; tükenince recvErr (varsayılan io.EOF) döner.
type fakeStream struct {
	grpc.ServerStream
	ctx     context.Context
	batches []*kutv1.EventBatch
	i       int
	recvErr error
	ack     *kutv1.EventAck
}

func (s *fakeStream) Context() context.Context { return s.ctx }
func (s *fakeStream) Recv() (*kutv1.EventBatch, error) {
	if s.i < len(s.batches) {
		b := s.batches[s.i]
		s.i++
		return b, nil
	}
	if s.recvErr != nil {
		return nil, s.recvErr
	}
	return nil, io.EOF
}
func (s *fakeStream) SendAndClose(a *kutv1.EventAck) error {
	s.ack = a
	return nil
}
