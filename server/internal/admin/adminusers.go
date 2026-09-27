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

	"kut.corp/suite/server/internal/security"
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
	effTenant := tenantID
	if creatorTenant != "" {
		// Kiracıya bağlı admin: başka kiracıya admin ekleyemez (fail-closed, denetlenebilir).
		if tenantID != "" && tenantID != creatorTenant {
			return "", ErrForbidden
		}
		// Boş istek "kendi kiracım" demektir.
		effTenant = creatorTenant
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

// SetAdminRole, bir yöneticinin rolünü değiştirir (ADMIN).
func (s *Service) SetAdminRole(ctx context.Context, adminID, targetID string, role Role) error {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return err
	}
	if !validAdminRole(role) {
		return ErrInvalidInput
	}
	if err := s.store.SetAdminRole(ctx, targetID, role); err != nil {
		return err
	}
	s.audit(ctx, adminID, "SET_ADMIN_ROLE", "admin", targetID)
	return nil
}

// DeactivateAdmin, bir yöneticiyi pasifleştirir (is_active=false) (ADMIN).
// Pasif yönetici artık oturum açamaz ve yetki denetimlerinden geçemez.
func (s *Service) DeactivateAdmin(ctx context.Context, adminID, targetID string) error {
	if err := s.require(ctx, adminID, RoleAdmin); err != nil {
		return err
	}
	if err := s.store.DeactivateAdmin(ctx, targetID); err != nil {
		return err
	}
	s.audit(ctx, adminID, "DEACTIVATE_ADMIN", "admin", targetID)
	return nil
}

// ListAdmins, tüm yöneticileri döner (OPERATOR+). Parola hash'i ASLA dönmez.
func (s *Service) ListAdmins(ctx context.Context, adminID string) ([]AdminView, error) {
	if err := s.require(ctx, adminID, RoleOperator); err != nil {
		return nil, err
	}
	infos, err := s.store.ListAdmins(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]AdminView, 0, len(infos))
	for _, a := range infos {
		out = append(out, AdminView{ID: a.ID, Email: a.Email, Role: a.Role, Active: a.Active})
	}
	return out, nil
}
