package admin

import (
	"context"
	"errors"
	"testing"
	"time"
)

// yeniden kayıtta yeni sır BEKLEYEN olarak ayrı tutulur; etkin sır ve enrolled=true,
// yeni sır YENİ sırdan geçerli bir kodla etkinleştirilene dek aynen kalır (MFA hiçbir anda
// fiilen kapanmaz). Bu test, ayrı-bekleyen-sır tasarımı olmadan (eski davranış: enrolled=false)
// başarısız olur.
func TestMFAReenrollKeepsOldSecretActiveUntilNewActivated(t *testing.T) {
	ctx := context.Background()
	svc, store := wallFixture(t)
	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	clock := t0
	svc.now = func() time.Time { return clock }

	const oldSecret = "JBSWY3DPEHPK3PXP"
	store.admins["acme-op"].mfaSecret = oldSecret
	store.admins["acme-op"].mfaEnrolled = true

	// Yeniden kayıt (mevcut sırdan geçerli kod ile).
	newSecret, _, err := svc.BeginMFAEnrollment(ctx, "acme-op", totpFor(t, oldSecret, clock))
	if err != nil || newSecret == "" || newSecret == oldSecret {
		t.Fatalf("yeniden kayıt başlamalı ve yeni sır üretmeli: %q %v", newSecret, err)
	}

	// Bekleyen pencere: eski sır HÂLÂ etkin ve enrolled=true; yeni sır yalnız bekleyen.
	// (Giriş yolu LookupMFA'ya bakar → MFA zorunluluğu sürer.)
	a := store.admins["acme-op"]
	if !a.mfaEnrolled || a.mfaSecret != oldSecret || a.mfaPending != newSecret {
		t.Fatalf("bekleyen pencerede eski sır etkin kalmalı: enrolled=%v secret=%q pending=%q", a.mfaEnrolled, a.mfaSecret, a.mfaPending)
	}
	sec, on, _ := store.LookupMFA(ctx, "acme-op")
	if !on || sec != oldSecret {
		t.Fatalf("LookupMFA (giriş yolu) bekleyen pencerede eski sırrı+enrolled=true dönmeli: %q/%v", sec, on)
	}

	// Disable: keyfi kod ile ASLA; bekleyen (YENİ) sırdan gelen kodla da DEĞİL — yalnız
	// ŞU AN ETKİN (eski) sırdan.
	clock = t0.Add(30 * time.Second)
	if err := svc.DisableMFA(ctx, "acme-op", "000000"); !errors.Is(err, ErrForbidden) {
		t.Fatalf("bekleyen pencerede keyfi kodla disable reddedilmeli: %v", err)
	}
	if err := svc.DisableMFA(ctx, "acme-op", totpFor(t, newSecret, clock)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("bekleyen (yeni) sırdan gelen kod disable'ı geçmemeli: %v", err)
	}
	if err := svc.DisableMFA(ctx, "acme-op", ""); !errors.Is(err, ErrForbidden) {
		t.Fatalf("boş kodla disable reddedilmeli: %v", err)
	}
	if !a.mfaEnrolled || a.mfaSecret != oldSecret {
		t.Fatal("reddedilen disable MFA durumunu değiştirmemeli")
	}

	// Aktivasyon: ESKİ sırdan gelen kod yeni sırrı etkinleştiremez; YENİ sırdan gelen kod eder.
	if err := svc.ActivateMFA(ctx, "acme-op", totpFor(t, oldSecret, clock)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("eski sırdan gelen kod bekleyen sırrı etkinleştirmemeli: %v", err)
	}
	if a.mfaSecret != oldSecret || a.mfaPending != newSecret {
		t.Fatal("başarısız aktivasyon takas yapmamalı")
	}
	if err := svc.ActivateMFA(ctx, "acme-op", totpFor(t, newSecret, clock)); err != nil {
		t.Fatalf("yeni sırdan gelen geçerli kod etkinleştirmeli: %v", err)
	}
	if !a.mfaEnrolled || a.mfaSecret != newSecret || a.mfaPending != "" {
		t.Fatalf("takas sonrası yeni sır etkin, bekleyen boş olmalı: secret=%q pending=%q enrolled=%v", a.mfaSecret, a.mfaPending, a.mfaEnrolled)
	}

	// Takastan sonra ESKİ sırdan gelen kod artık çalışmaz (taze, kullanılmamış adımda bile).
	clock = t0.Add(120 * time.Second)
	if err := svc.DisableMFA(ctx, "acme-op", totpFor(t, oldSecret, clock)); !errors.Is(err, ErrForbidden) {
		t.Fatalf("takastan sonra eski sır kodu reddedilmeli: %v", err)
	}
	if !a.mfaEnrolled {
		t.Fatal("eski kodla disable MFA'yı kapatmamalı")
	}
	// Yeni sırdan gelen kod kapatır.
	if err := svc.DisableMFA(ctx, "acme-op", totpFor(t, newSecret, clock)); err != nil {
		t.Fatalf("yeni sırdan gelen kod disable etmeli: %v", err)
	}
	if a.mfaEnrolled || a.mfaSecret != "" || a.mfaPending != "" {
		t.Fatalf("disable etkin+bekleyen sırrı temizlemeli: %+v", a)
	}
}

// Terk edilen yeniden kayıt MFA'yı kapatmaz: kullanıcı hiç aktive etmezse bile etkin sır
// ve enrolled=true kalır; yeni bir Begin bekleyen sırrı yalnız DEĞİŞTİRİR.
func TestMFAAbandonedReenrollLeavesMFAOn(t *testing.T) {
	ctx := context.Background()
	svc, store := wallFixture(t)
	t0 := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	clock := t0
	svc.now = func() time.Time { return clock }
	const oldSecret = "JBSWY3DPEHPK3PXP"
	a := store.admins["acme-op"]
	a.mfaSecret, a.mfaEnrolled = oldSecret, true

	first, _, err := svc.BeginMFAEnrollment(ctx, "acme-op", totpFor(t, oldSecret, clock))
	if err != nil {
		t.Fatal(err)
	}
	clock = t0.Add(60 * time.Second)
	second, _, err := svc.BeginMFAEnrollment(ctx, "acme-op", totpFor(t, oldSecret, clock))
	if err != nil {
		t.Fatalf("ikinci yeniden kayıt (eski sırdan kod) geçmeli: %v", err)
	}
	if first == second || a.mfaPending != second {
		t.Fatal("ikinci Begin bekleyen sırrı değiştirmeli")
	}
	if !a.mfaEnrolled || a.mfaSecret != oldSecret {
		t.Fatal("hiç aktive edilmeyen yeniden kayıt MFA'yı kapatmamalı")
	}
	// İlk (artık geçersiz) bekleyen sırdan kod aktive edemez.
	if err := svc.ActivateMFA(ctx, "acme-op", totpFor(t, first, clock.Add(30*time.Second))); !errors.Is(err, ErrForbidden) {
		t.Fatalf("değiştirilmiş bekleyen sırdan kod reddedilmeli: %v", err)
	}
}
