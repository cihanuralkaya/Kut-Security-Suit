// Package privman, güvenlik sonucu doğuran server-side/cihaz side-effect'lerini tek
// yaptırımlı sınırda toplamak için `PrivilegedMutation` kavramını tanımlar (Milestone A
// / PR-02; audit docs/security/PR01_DELTA_AUDIT.md §1). Amaç G-02'nin KÖK NEDENİNİ
// kapatmaktır: bugün raw Store mutasyonları (EnqueueCommand*, SetDeviceStatus,
// AssignPolicy, EraseDeviceData, RevokeDeviceCerts...) export edilmiş olduğundan Store'u
// tutan HERHANGİ bir paket authorization sınırını atlayarak çağırabilir.
//
// Bu paket ADDITIVE ve DAVRANIŞ-KORUYANDIR: yalnız BARİYER + tipler + testler. Henüz
// hiçbir production executor buraya bağlı değil (PR-03+ bağlar). Bariyer iki katmanlıdır:
//  1. Sealed interface (unexported `sealed()` marker) → dış paketler PrivilegedMutation'ı
//     DERLEME ZAMANINDA implemente edemez; mutasyonlar yalnız buradaki constructor'lardan doğar.
//  2. Mimari fitness testi (guard_test.go) → raw mutasyonların yalnız bilinen sınır
//     paketlerinde çağrıldığını doğrular; yeni bir bypass eklenirse CI kırılır.
package privman

import "kut.corp/suite/server/internal/scope"

// SideEffectClass, bir privileged mutasyonun güvenlik sonucu sınıfıdır (audit §1).
type SideEffectClass string

const (
	ClassDeviceCommand         SideEffectClass = "DEVICE_COMMAND"               // EnqueueCommand* (WIPE/QUARANTINE/LOCK/RESTART/COLLECT_*)
	ClassSecurityStateMutation SideEffectClass = "SECURITY_STATE_MUTATION"      // SetDeviceStatus(QUARANTINED), SavePendingWipe/DeletePendingWipe
	ClassDestructiveServer     SideEffectClass = "DESTRUCTIVE_SERVER_MUTATION"  // EraseDeviceData
	ClassIdentityCredential    SideEffectClass = "IDENTITY_CREDENTIAL_MUTATION" // RevokeDeviceCerts, RevokeEnrollmentToken
	ClassPolicyMutation        SideEffectClass = "POLICY_MUTATION"              // AssignPolicy (+ dolaylı agent push)
	ClassMetadataOnly          SideEffectClass = "METADATA_ONLY"                // SetDeviceTags, SetEventAck
)

// RequiresGuardedBoundary, bu sınıfın GuardedExecutor'dan (grant + ExecutionIntent)
// geçmesi gerekip gerekmediğini döner (audit §1). Yalnız METADATA_ONLY sınırı ATLAYABİLİR
// (yine RBAC+tenant+audit'e tabidir, başka katmanda); geri kalan her şey grant gerektirir.
func (c SideEffectClass) RequiresGuardedBoundary() bool { return c != ClassMetadataOnly }

// PrivilegedMutation, güvenlik sonucu doğuran bir mutasyonun SEALED tanımlayıcısıdır.
// Sealed'dır (unexported `sealed()` marker): privman DIŞINDAki hiçbir paket bu arayüzü
// implemente edemez → privileged mutasyon yalnız buradaki constructor'lardan doğar
// (G-02 bariyerinin derleme-zamanı yarısı).
type PrivilegedMutation interface {
	Class() SideEffectClass // güvenlik sonucu sınıfı
	Kind() string           // operasyon adı (ör. "wipe", "set_device_status", "assign_policy")
	Targets() []string      // etkilenen cihaz kimlikleri
	Destructive() bool      // geri döndürülemez side-effect (ek fail-closed gereksinimleri)
	sealed()                // unexported: dış implementasyonu derleme zamanında engeller
}

// mutation, PrivilegedMutation'ın tek somut (unexported) gerçekleştirimidir.
type mutation struct {
	class       SideEffectClass
	kind        string
	targets     []string
	destructive bool
}

func (m mutation) Class() SideEffectClass { return m.class }
func (m mutation) Kind() string           { return m.kind }
func (m mutation) Targets() []string      { return append([]string(nil), m.targets...) }
func (m mutation) Destructive() bool      { return m.destructive }
func (mutation) sealed()                  {}

// NewDeviceCommand, bir cihaz komutu mutasyonu üretir (DEVICE_COMMAND). Destructive,
// aksiyonun etki sınıfından server-side türetilir (WIPE/exploitation → destructive).
func NewDeviceCommand(action scope.Action, targets ...string) PrivilegedMutation {
	return mutation{
		class: ClassDeviceCommand, kind: string(action), targets: targets,
		destructive: scope.ImpactOf(action) >= scope.Destructive,
	}
}

// NewSecurityStateMutation, güvenlik-durumu mutasyonu üretir (SECURITY_STATE_MUTATION;
// ör. SetDeviceStatus(QUARANTINED), SavePendingWipe).
func NewSecurityStateMutation(kind string, targets ...string) PrivilegedMutation {
	return mutation{class: ClassSecurityStateMutation, kind: kind, targets: targets}
}

// NewDestructiveServerMutation, yıkıcı server mutasyonu üretir (DESTRUCTIVE_SERVER_MUTATION;
// ör. EraseDeviceData). Daima destructive=true → fail-closed + journal gerektirir.
func NewDestructiveServerMutation(kind string, targets ...string) PrivilegedMutation {
	return mutation{class: ClassDestructiveServer, kind: kind, targets: targets, destructive: true}
}

// NewIdentityCredentialMutation, kimlik/kredensiyel mutasyonu üretir
// (IDENTITY_CREDENTIAL_MUTATION; ör. RevokeDeviceCerts, RevokeEnrollmentToken).
func NewIdentityCredentialMutation(kind string, targets ...string) PrivilegedMutation {
	return mutation{class: ClassIdentityCredential, kind: kind, targets: targets}
}

// NewPolicyMutation, politika mutasyonu üretir (POLICY_MUTATION; ör. AssignPolicy).
// Dolaylı cihaz push'u olduğundan sınır gerektirir (audit F-A).
func NewPolicyMutation(kind string, targets ...string) PrivilegedMutation {
	return mutation{class: ClassPolicyMutation, kind: kind, targets: targets}
}

// NewMetadataMutation, güvenlik-sonucu düşük metadata mutasyonu üretir (METADATA_ONLY;
// ör. SetDeviceTags, SetEventAck). Grant gerektirmez (yine RBAC+tenant+audit).
func NewMetadataMutation(kind string, targets ...string) PrivilegedMutation {
	return mutation{class: ClassMetadataOnly, kind: kind, targets: targets}
}
