package controlplane

import (
	"context"
	"strings"
	"time"

	"kut.corp/suite/server/internal/security"
)

// AuthStatus, kanonik admin kimlik doğrulamanın sonucudur. Transport (HTTP) katmanı
// bu duruma göre throttling hesaplar, hata mesajı seçer ve oturum üretir.
type AuthStatus int

const (
	// AuthInvalid, bilinmeyen hesap veya yanlış paroladır (ayırt edilmez — numaralandırma kapalı).
	AuthInvalid AuthStatus = iota
	// AuthMFARequired, parola doğru + MFA etkin ama ikinci-faktör kodu verilmedi.
	AuthMFARequired
	// AuthMFAInvalidCode, verilen TOTP kodu geçersiz.
	AuthMFAInvalidCode
	// AuthMFAReplay, TOTP kodu geçerli ama bu adım zaten kullanıldı (anti-replay).
	AuthMFAReplay
	// AuthOK, kimlik + (varsa) MFA tam doğrulandı.
	AuthOK
)

// AuthResult, Authenticate çıktısıdır. AdminID yalnız parola doğrulandığında doludur.
type AuthResult struct {
	Status  AuthStatus
	AdminID string
}

// CredentialStore, e-postadan admin kimliğini ve Argon2 parola hash'ini çözer.
type CredentialStore interface {
	LookupAdmin(ctx context.Context, email string) (adminID, passwordHash string, err error)
}

// MFAVerifier, ikinci-faktör (TOTP) durumunu çözer ve anti-replay adımını tüketir.
// nil enjekte edilirse MFA devre dışıdır (geriye uyumlu).
type MFAVerifier interface {
	LookupMFA(ctx context.Context, adminID string) (secret string, enrolled bool, err error)
	ConsumeTOTPStep(ctx context.Context, adminID string, step int64) (accepted bool, err error)
}

// Authenticator, admin kimlik doğrulamanın KANONİK otoritesidir: sabit-zaman parola
// doğrulama (kullanıcı-numaralandırma yan-kanalı kapalı), MFA zorlaması ve TOTP
// anti-replay'i tek yerde toplar. Transport-seviyesi throttling (IP+e-posta kaba-kuvvet)
// BURAYA ait DEĞİLDİR — o, HTTP uç noktasını koruyan adminapi'nin sorumluluğudur.
type Authenticator struct {
	creds     CredentialStore
	mfa       MFAVerifier
	now       func() time.Time
	dummyHash string // bilinmeyen hesapta sabit-zaman için kukla Argon2 hash
}

// NewAuthenticator, kanonik kimlik doğrulayıcı kurar. mfa nil ise MFA kapalıdır.
// dummyHash, bilinmeyen hesapta da Argon2 maliyetini ödeyip zamanlama yan-kanalını
// kapatmak için geçerli biçimli bir kukla hash olmalıdır. now nil ise time.Now.
func NewAuthenticator(creds CredentialStore, mfa MFAVerifier, dummyHash string, now func() time.Time) *Authenticator {
	if now == nil {
		now = time.Now
	}
	return &Authenticator{creds: creds, mfa: mfa, now: now, dummyHash: dummyHash}
}

// Authenticate, bir admin'i parola + (varsa) MFA ile doğrular. code MFA kodudur
// (MFA etkin değilse yok sayılır). Hata yalnız altyapı arızasında döner (depo/MFA
// okuma); kimlik/MFA başarısızlığı err=nil + uygun AuthStatus ile raporlanır.
func (a *Authenticator) Authenticate(ctx context.Context, email, password, code string) (AuthResult, error) {
	adminID, hash, err := a.creds.LookupAdmin(ctx, strings.TrimSpace(email))
	if err != nil {
		return AuthResult{}, err
	}
	if adminID == "" {
		// Sabit-zaman: bilinmeyen/pasif hesapta da Argon2 maliyetini öde (sonuç yok
		// sayılır) — kullanıcı numaralandırma yan-kanalını kapatır.
		_, _ = security.VerifyPassword(a.dummyHash, password)
		return AuthResult{Status: AuthInvalid}, nil
	}
	ok, err := security.VerifyPassword(hash, password)
	if err != nil || !ok {
		return AuthResult{Status: AuthInvalid}, nil
	}

	// İkinci faktör (TOTP): parola doğruysa ve hesapta MFA etkinse zorunludur.
	if a.mfa != nil {
		secret, enrolled, err := a.mfa.LookupMFA(ctx, adminID)
		if err != nil {
			return AuthResult{}, err
		}
		if enrolled {
			if strings.TrimSpace(code) == "" {
				return AuthResult{Status: AuthMFARequired, AdminID: adminID}, nil
			}
			step, vok := security.VerifyTOTPStep(secret, code, a.now())
			if !vok {
				return AuthResult{Status: AuthMFAInvalidCode, AdminID: adminID}, nil
			}
			accepted, err := a.mfa.ConsumeTOTPStep(ctx, adminID, step)
			if err != nil {
				return AuthResult{}, err
			}
			if !accepted {
				return AuthResult{Status: AuthMFAReplay, AdminID: adminID}, nil
			}
		}
	}
	return AuthResult{Status: AuthOK, AdminID: adminID}, nil
}
