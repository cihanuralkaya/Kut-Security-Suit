package admin

// Bu dosya, yönetici (admin) kullanıcı yönetimini içerir: yeni admin oluşturma,
// rol değiştirme, pasifleştirme ve listeleme. Tüm mutasyonlar RoleAdmin gerektirir
// ve denetim izine (audit_log) yazar; listeleme RoleOperator+ ile açıktır.
//
// Parola ASLA düz metin saklanmaz: CreateAdmin, security.HashPassword (Argon2id)
// ile hash üretir ve yalnız hash'i depoya verir. Okuma yollarında (AdminView /
// ListAdmins) parola hash'i HİÇBİR zaman dışa sızmaz.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"kut.corp/suite/server/internal/security"
	"kut.corp/suite/server/internal/tenant"
)

// ErrInvalidInput, kullanıcı girdisi doğrulamayı geçemediğinde döner
// (boş e-posta, çok kısa parola veya geçersiz rol) — istemci hatası (400).
var ErrInvalidInput = errors.New("admin: geçersiz girdi")

// minPasswordLen, yeni yönetici parolası için asgari uzunluktur.
const minPasswordLen = 8

// AdminInfo, Store'un ListAdmins'ten döndürdüğü ham satırdır (parola hash'i YOK).
type AdminInfo struct {
	ID     string
	Email  string
	Role   Role
	Active bool
}

// AdminView, bir yöneticinin okunabilir görünümüdür. Parola hash'i ASLA içermez.
type AdminView struct {
	ID     string `json:"id"`
	Email  string `json:"email"`
	Role   Role   `json:"role"`
	Active bool   `json:"active"`
}

// validAdminRole, kabul edilen yönetici rollerini doğrular.
func validAdminRole(r Role) bool {
	switch r {
	case RoleViewer, RoleOperator, RoleAdmin:
		return true
	default:
		return false
	}
}

// CreateAdmin, yeni bir yönetici oluşturur (ADMIN). Parola boş/kısa ya da rol
// geçersizse ErrInvalidInput döner. Parola Argon2id ile hash'lenir ve YALNIZ hash
// depoya yazılır (düz metin asla). Yeni yöneticinin id'sini döner.
func (s *Service) CreateAdmin(ctx context.Context, adminID, email, password string, role Role, tenantID string) (string, error) {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return "", err
	}
	if email == "" || len(password) < minPasswordLen || !validAdminRole(role) {
		return "", ErrInvalidInput
	}
	// Kiracıyı oluşturan yöneticinin kendi kiracısı belirler (ayrıcalık-yükseltme koruması):
	// platform admini (boş kiracı) herhangi bir kiracı atayabilir; kiracıya bağlı bir
	// admin yalnızca kendi kiracısında admin oluşturabilir, başka kiracıya sızamaz.
	creatorTenant, err := s.store.AdminTenant(ctx, adminID)
	if err != nil {
		return "", err
	}
	// Z4b-08: istekten gelen kiracı değeri tenant.Normalize ile kırpılır/küçük harfe çevrilir/
	// doğrulanır (büyük-küçük harf varyantları ayrı kiracı olamaz; VARCHAR(63) taşması 500 olmaz).
	// Boş istek burada boş KALIR: boş kiracı = platform admini (Normalize'ın "default"una
	// çevrilmez).
	effTenant := strings.TrimSpace(tenantID)
	if creatorTenant != "" {
		// Kiracıya bağlı admin: başka kiracıya admin ekleyemez (fail-closed, denetlenebilir).
		if effTenant != "" {
			n, nerr := tenant.Normalize(effTenant)
			if effTenant != creatorTenant && (nerr != nil || string(n) != creatorTenant) {
				return "", ErrForbidden
			}
		}
		// Boş istek "kendi kiracım" demektir.
		effTenant = creatorTenant
	} else if effTenant != "" {
		n, nerr := tenant.Normalize(effTenant)
		if nerr != nil {
			return "", ErrInvalidInput
		}
		effTenant = string(n)
	}
	hash, err := security.HashPassword(password)
	if err != nil {
		return "", err
	}
	newID, err := s.store.CreateAdmin(ctx, email, hash, role, effTenant)
	if err != nil {
		return "", err
	}
	s.audit(ctx, adminID, "CREATE_ADMIN", "admin", newID)
	return newID, nil
}

// AdminTenant, bir yöneticinin bağlı olduğu kiracıyı döner (okuma-yolu kapsamı için).
// Boş → platform admini (tüm kiracıları görür). RBAC gerektirmez: çağıran zaten kimlik
// doğrulanmış kendi id'sini sorgular; sonuç yalnız okuma-filtresini daraltmakta kullanılır.
func (s *Service) AdminTenant(ctx context.Context, adminID string) (string, error) {
	return s.store.AdminTenant(ctx, adminID)
}

// enforceAdminTarget, bir yönetici-yönetimi mutasyonunun (rol değiştir / pasifleştir)
// kiracı sınırını doğrular ve çağıranın kiracısını döner. Platform admini (kiracısız)
// kısıtsızdır. Kiracıya bağlı bir admin YALNIZ kendi kiracısının yöneticilerine dokunabilir:
// hedefin kiracısı boş (platform admini) ya da başka bir kiracı ya da bilinmeyen/pasif
// hedef → ErrForbidden (fail-closed; CreateAdmin'in kiracı korumasının aynası).
func (s *Service) enforceAdminTarget(ctx context.Context, adminID, targetID string) (string, error) {
	callerTenant, err := s.store.AdminTenant(ctx, adminID)
	if err != nil {
		return "", err
	}
	if callerTenant == "" {
		return "", nil // platform admini: kısıtsız
	}
	targetTenant, err := s.store.AdminTenant(ctx, targetID)
	if err != nil {
		return "", err
	}
	if targetTenant == "" || targetTenant != callerTenant {
		return "", ErrForbidden
	}
	return callerTenant, nil
}

// ErrLastAdmin, bir yöneticinin kendi ADMIN yetkisini (rol düşürme / pasifleştirme ile)
// kaldırmasının, kapsamındaki SON etkin ADMIN'i yok edeceği durumda döner. ErrForbidden'ı
// sarar (HTTP 403): kiracı (veya platform) yönetimsiz kalıp kilitlenmesin.
var ErrLastAdmin = fmt.Errorf("%w: kapsamdaki son etkin ADMIN kendi yetkisini kaldıramaz", ErrForbidden)

// hasOtherActiveAdmin, adminID dışında, adminID ile AYNI kapsamda (kiracı; platform
// adminleri için boş kiracı) en az bir ETKİN ADMIN olup olmadığını döner. Fail-closed:
// okuma hatası çağırana yayılır (guard "var" demez).
func (s *Service) hasOtherActiveAdmin(ctx context.Context, adminID, tenantID string) (bool, error) {
	infos, err := s.store.ListAdmins(ctx, tenantID)
	if err != nil {
		return false, err
	}
	for _, a := range infos {
		if a.ID == adminID || !a.Active || a.Role != RoleAdmin {
			continue
		}
		if tenantID == "" {
			// Boş kiracı filtresi TÜM yöneticileri döner; platform kapsamı yalnız boş
			// kiracılı adminlerdir (kiracılı bir admin platformu yönetemez).
			t, err := s.store.AdminTenant(ctx, a.ID)
			if err != nil {
				return false, err
			}
			if t != "" {
				continue
			}
		}
		return true, nil
	}
	return false, nil
}

// guardLastAdmin, bir yöneticinin KENDİNİ ADMIN'likten çıkarmasını (rol düşürme veya
// pasifleştirme) kapsamındaki son etkin ADMIN ise engeller (Z4a-01 kendini-düşürme /
// son-admin koruması). Hedef çağıranın kendisi değilse hiçbir şey yapmaz: başka bir
// yönetici üzerinde işlem yapan ADMIN çağıran zaten kapsamda kalır.
func (s *Service) guardLastAdmin(ctx context.Context, adminID, targetID, callerTenant string) error {
	if adminID != targetID {
		return nil
	}
	other, err := s.hasOtherActiveAdmin(ctx, adminID, callerTenant)
	if err != nil {
		return err
	}
	if !other {
		return ErrLastAdmin
	}
	return nil
}

// SetAdminRole, bir yöneticinin rolünü değiştirir (ADMIN). Kiracıya bağlı bir admin yalnız
// kendi kiracısındaki yöneticilerin rolünü değiştirebilir (enforceAdminTarget): başka kiracıya
// veya platform adminlerine ADMIN dahil hiçbir rol veremez. Kendi rolünü ADMIN'in altına
// düşürmek, kapsamındaki SON etkin ADMIN ise reddedilir (ErrLastAdmin).
func (s *Service) SetAdminRole(ctx context.Context, adminID, targetID string, role Role) error {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return err
	}
	if !validAdminRole(role) {
		return ErrInvalidInput
	}
	callerTenant, err := s.enforceAdminTarget(ctx, adminID, targetID)
	if err != nil {
		return err
	}
	if role != RoleAdmin {
		if err := s.guardLastAdmin(ctx, adminID, targetID, callerTenant); err != nil {
			return err
		}
	}
	if err := s.store.SetAdminRole(ctx, targetID, role, callerTenant); err != nil {
		return err
	}
	s.audit(ctx, adminID, "SET_ADMIN_ROLE", "admin", targetID)
	return nil
}

// DeactivateAdmin, bir yöneticiyi pasifleştirir (is_active=false) (ADMIN).
// Pasif yönetici artık oturum açamaz ve yetki denetimlerinden geçemez. Kiracıya bağlı
// bir admin yalnız kendi kiracısının yöneticilerini pasifleştirebilir. Kendini pasifleştirmek,
// kapsamındaki SON etkin ADMIN ise reddedilir (ErrLastAdmin).
func (s *Service) DeactivateAdmin(ctx context.Context, adminID, targetID string) error {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return err
	}
	callerTenant, err := s.enforceAdminTarget(ctx, adminID, targetID)
	if err != nil {
		return err
	}
	if err := s.guardLastAdmin(ctx, adminID, targetID, callerTenant); err != nil {
		return err
	}
	if err := s.store.DeactivateAdmin(ctx, targetID, callerTenant); err != nil {
		return err
	}
	s.audit(ctx, adminID, "DEACTIVATE_ADMIN", "admin", targetID)
	return nil
}

// ListAdmins, yöneticileri döner (OPERATOR+). Platform admini hepsini görür; kiracıya
// bağlı çağıran YALNIZ kendi kiracısının yöneticilerini görür (platform adminleri ve
// diğer kiracılar listelenmez). Parola hash'i ASLA dönmez.
func (s *Service) ListAdmins(ctx context.Context, adminID string) ([]AdminView, error) {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return nil, err
	}
	callerTenant, err := s.store.AdminTenant(ctx, adminID)
	if err != nil {
		return nil, err
	}
	infos, err := s.store.ListAdmins(ctx, callerTenant)
	if err != nil {
		return nil, err
	}
	out := make([]AdminView, 0, len(infos))
	for _, a := range infos {
		out = append(out, AdminView{ID: a.ID, Email: a.Email, Role: a.Role, Active: a.Active})
	}
	return out, nil
}
