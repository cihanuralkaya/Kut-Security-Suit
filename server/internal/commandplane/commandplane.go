package commandplane

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// GuardedCommandSink, yetkilendirilmiş + imzalanmış bir komut zarfını KANONİK
// korumalı sınırdan (admin/adminapi → privman/GuardedExecutor → Store) geçirerek
// kuyruğa ekler. Bu arayüzün PRODUCTION gerçekleştirimi YALNIZ bir sınır paketinde
// (server/internal/admin veya adminapi) yaşamalıdır — commandplane'in kendisi raw
// Store mutasyonu (EnqueueCommand) ÇAĞIRMAZ (G-02 bariyeri: audit §1/§4). Böylece
// komut düzlemi gölge bir yetki/depo yolu oluşturmaz; tek yaptırımlı sınırdan geçer.
type GuardedCommandSink interface {
	// DispatchSigned, imzalı+yetkili zarfı korumalı sınırdan kuyruğa ekler ve
	// atanan komut kimliğini döner.
	DispatchSigned(ctx context.Context, env SignedCommandEnvelope) (string, error)
	// AckResult, bir komutun sonuç durumunu günceller (ACK).
	AckResult(ctx context.Context, commandID string, status CommandState, detail string) error
	// GetPendingCommands, bir cihazın bekleyen komutlarını döner (salt-okuma).
	GetPendingCommands(ctx context.Context, deviceID string) ([]CommandRecord, error)
}

// AuthorizationDecision represents a basic decision.
type AuthorizationDecision struct {
	Allowed bool
	Reason  string
}

// ActionRequest represents a request for authorization.
type ActionRequest struct {
	Subject string // IssuedBy
	Action  string // CommandType
	Object  string // DeviceID
}

// Authorizer, yetki kararı arayüzüdür. PRODUCTION wiring'inde buraya KANONİK
// authz/secgateway adaptörü enjekte EDİLMELİDİR — izin-veren bir stub DEĞİL.
// Dormant kaldığı sürece hiçbir karar üretilmez (plane bağlı değil).
type Authorizer interface {
	Authorize(ctx context.Context, req ActionRequest) (AuthorizationDecision, error)
}

// Plane encapsulates the command plane logic.
type Plane struct {
	sink    GuardedCommandSink
	authz   Authorizer
	signer  *CommandSigner
	mu      sync.RWMutex
	running bool
}

// NewPlane creates a new CommandPlane instance. authz ve signer ZORUNLUDUR
// (nil ise Dispatch fail-closed reddeder) — imzasız/yetkisiz komut üretilemez.
func NewPlane(sink GuardedCommandSink, authz Authorizer, signer *CommandSigner) *Plane {
	return &Plane{
		sink:   sink,
		authz:  authz,
		signer: signer,
	}
}

// Start starts the command plane.
func (p *Plane) Start(ctx context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		return errors.New("command plane already running")
	}
	p.running = true
	return nil
}

// Stop stops the command plane.
func (p *Plane) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.running {
		return errors.New("command plane not running")
	}
	p.running = false
	return nil
}

// Dispatch validates the request, checks authorization, cryptographically signs
// the command, and enqueues it THROUGH the guarded boundary sink. Fail-closed:
// eksik yetkilendirici/imzalayıcı/sink veya reddedilen yetki → komut üretilmez.
func (p *Plane) Dispatch(ctx context.Context, req CommandRequest) (string, error) {
	if err := req.Validate(); err != nil {
		return "", err
	}
	if p.authz == nil || p.signer == nil || p.sink == nil {
		return "", errors.New("command plane not fully configured (authz/signer/sink required)")
	}

	authReq := ActionRequest{
		Subject: req.IssuedBy,
		Action:  string(req.Type),
		Object:  req.DeviceID,
	}

	// Yetki kontrolü (fail-closed).
	decision, err := p.authz.Authorize(ctx, authReq)
	if err != nil {
		return "", err
	}
	if !decision.Allowed {
		return "", errors.New("authorization denied: " + decision.Reason)
	}

	// Kriptografik imza ZORUNLU (non-repudiation + integrity). İmzalanmamış komut
	// korumalı sınıra gönderilmez.
	cmdID, err := newCommandID()
	if err != nil {
		return "", err
	}
	env, err := p.signer.Sign(cmdID, req, time.Now())
	if err != nil {
		return "", err
	}

	// Yetki başarılı + imzalı → KANONİK korumalı sınırdan kuyruğa ekle.
	return p.sink.DispatchSigned(ctx, env)
}

// HandleCommandResult updates the command status based on the result.
func (p *Plane) HandleCommandResult(ctx context.Context, deviceID, commandID string, success bool, detail string) error {
	if p.sink == nil {
		return errors.New("command plane not configured (sink required)")
	}
	status := StateFailed
	if success {
		status = StateSucceeded
	}
	return p.sink.AckResult(ctx, commandID, status, detail)
}

// newCommandID, kriptografik rastgele bir komut kimliği üretir (imzalama zarfının
// CommandID'si; kuyruk atamasından ÖNCE gerekir çünkü imza bu id'yi bağlar).
func newCommandID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return "cmd-" + hex.EncodeToString(b[:]), nil
}
