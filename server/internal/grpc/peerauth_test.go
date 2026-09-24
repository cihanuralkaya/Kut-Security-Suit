package grpc

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

// TestDeviceIDFromContextSuccess, doğrulanmış istemci sertifikasının CN'inin
// device_id olarak çıkarıldığını doğrular (güven sınırı).
func TestDeviceIDFromContextSuccess(t *testing.T) {
	id, err := DeviceIDFromContext(peerCtx("dev-1"))
	if err != nil {
		t.Fatalf("beklenmeyen hata: %v", err)
	}
	if id != "dev-1" {
		t.Fatalf("device id = %q, beklenen dev-1", id)
	}
}

// TestDeviceIDFromContextNoPeer, context'te peer yoksa ErrNoPeerIdentity dönmeli.
func TestDeviceIDFromContextNoPeer(t *testing.T) {
	if _, err := DeviceIDFromContext(context.Background()); err != ErrNoPeerIdentity {
		t.Fatalf("peer yokken ErrNoPeerIdentity beklenirdi, dönen: %v", err)
	}
}

// TestDeviceIDFromContextNonTLS, AuthInfo TLS değilse ErrNoPeerIdentity dönmeli.
func TestDeviceIDFromContextNonTLS(t *testing.T) {
	ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: nonTLSAuth{}})
	if _, err := DeviceIDFromContext(ctx); err != ErrNoPeerIdentity {
		t.Fatalf("TLS-olmayan AuthInfo için ErrNoPeerIdentity beklenirdi, dönen: %v", err)
	}
}

// TestDeviceIDFromContextEmptyCN, sertifika CN'i boşsa (veya sertifika yoksa)
// ErrNoPeerIdentity dönmeli — gövdedeki device_id'ye asla güvenilmez.
func TestDeviceIDFromContextEmptyCN(t *testing.T) {
	// Boş CN.
	empty := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{{Subject: pkix.Name{CommonName: ""}}},
		}},
	})
	if _, err := DeviceIDFromContext(empty); err != ErrNoPeerIdentity {
		t.Fatalf("boş CN için ErrNoPeerIdentity beklenirdi, dönen: %v", err)
	}
	// Hiç sertifika yok.
	none := peer.NewContext(context.Background(), &peer.Peer{
		AuthInfo: credentials.TLSInfo{State: tls.ConnectionState{PeerCertificates: nil}},
	})
	if _, err := DeviceIDFromContext(none); err != ErrNoPeerIdentity {
		t.Fatalf("sertifikasız için ErrNoPeerIdentity beklenirdi, dönen: %v", err)
	}
}

// nonTLSAuth, credentials.AuthInfo'yu karşılar ama TLSInfo DEĞİLDİR.
type nonTLSAuth struct{}

func (nonTLSAuth) AuthType() string { return "insecure" }
