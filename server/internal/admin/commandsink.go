package admin

import (
	"context"
	"fmt"

	"kut.corp/suite/server/internal/commandplane"
)

// commandEnqueuer, korumalı sink'in ihtiyaç duyduğu asgari depo yüzeyidir
// (hem *db.Store hem *memstore.Store karşılar).
type commandEnqueuer interface {
	EnqueueCommandParams(ctx context.Context, deviceID, cmdType, issuedBy string, params map[string]string) error
}

// CommandSink, commandplane.GuardedCommandSink'in ÜRETİM gerçeklemesidir: imzalı +
// yetkili komut zarfını mevcut, KANITLANMIŞ komut-kuyruğu sınırına
// (store.EnqueueCommandParams) DELEGE eder. Komut düzlemi; imza + anti-replay +
// plane-authz'yi bu enqueue'nun ÜSTÜNE ekler, gerçek kuyruklama ise değişmeden
// kanıtlanmış yolda kalır. Böylece admin.service'teki çift-kontrol WIPE, scope/ROE
// guardrail ve audit hash-zinciri olduğu gibi korunur (delege et, tekrarlama).
//
// Yalnız DispatchSigned hot-path'tedir. AckResult/GetPendingCommands ajanın sonuç/
// polling yoluna aittir; o yol depoyu (proto Command modeli) DOĞRUDAN kullanır, komut
// düzleminden geçmez — bu yüzden burada sessiz no-op yerine açık hata dönerler.
type CommandSink struct {
	store commandEnqueuer
}

// NewCommandSink, verilen depo ile üretim komut sink'i oluşturur.
func NewCommandSink(store commandEnqueuer) *CommandSink {
	return &CommandSink{store: store}
}

// DispatchSigned, imzalı zarfı kanonik sınırdan kuyruğa ekler ve komut kimliğini döner.
// İmza+yetki commandplane.Dispatch tarafından zaten üretildi; sink enqueue eder.
func (c *CommandSink) DispatchSigned(ctx context.Context, env commandplane.SignedCommandEnvelope) (string, error) {
	if c == nil || c.store == nil {
		return "", fmt.Errorf("guarded command sink: depo yapılandırılmadı")
	}
	if err := c.store.EnqueueCommandParams(ctx, env.DeviceID, string(env.Type), env.IssuedBy, stringParams(env.Params)); err != nil {
		return "", err
	}
	return env.CommandID, nil
}

// AckResult, komut düzlemi üzerinden DESTEKLENMEZ (ajan sonuç yolu depoyu doğrudan kullanır).
func (c *CommandSink) AckResult(ctx context.Context, commandID string, status commandplane.CommandState, detail string) error {
	return fmt.Errorf("guarded command sink: AckResult komut düzlemi üzerinden desteklenmiyor")
}

// GetPendingCommands, komut düzlemi üzerinden DESTEKLENMEZ (ajan polling depoyu doğrudan kullanır).
func (c *CommandSink) GetPendingCommands(ctx context.Context, deviceID string) ([]commandplane.CommandRecord, error) {
	return nil, fmt.Errorf("guarded command sink: GetPendingCommands komut düzlemi üzerinden desteklenmiyor")
}

// stringParams, zarfın any-değerli parametrelerini depo için string haritasına çevirir.
func stringParams(in map[string]any) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		if s, ok := v.(string); ok {
			out[k] = s
		} else {
			out[k] = fmt.Sprintf("%v", v)
		}
	}
	return out
}

var _ commandplane.GuardedCommandSink = (*CommandSink)(nil)
