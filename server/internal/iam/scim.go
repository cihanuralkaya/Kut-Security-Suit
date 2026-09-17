package iam

import (
	"errors"
	"sync"
	"time"
)

// SCIM 2.0 çekirdek User şeması tanımlayıcısı (RFC 7643).
const (
	// SchemaUser, SCIM çekirdek User kaynağının şema URN'sidir.
	SchemaUser = "urn:ietf:params:scim:schemas:core:2.0:User"
	// ResourceTypeUser, meta.resourceType için User değeridir.
	ResourceTypeUser = "User"
)

// SCIM sağlama hataları.
var (
	// ErrUserExists, verilen id ile zaten bir kullanıcı varsa döner.
	ErrUserExists = errors.New("iam: SCIM kullanıcısı zaten var")
	// ErrUserNotFound, istenen kullanıcı bulunamazsa döner.
	ErrUserNotFound = errors.New("iam: SCIM kullanıcısı bulunamadı")
	// ErrSAMLNotImplemented, varsayılan SAML sağlayıcısı çağrıldığında döner.
	ErrSAMLNotImplemented = errors.New("iam: SAML onaylama doğrulaması gerçeklenmedi (entegrasyon dikişi)")
)

// Name, SCIM User'ın adının bileşenlerini tutar (RFC 7643 §4.1.1 alt kümesi).
type Name struct {
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

// Email, SCIM çok-değerli e-posta girdisidir.
type Email struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

// Meta, SCIM kaynak meta verisidir (RFC 7643 §3.1).
type Meta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created,omitempty"`
	LastModified time.Time `json:"lastModified,omitempty"`
}

// User, SCIM 2.0 çekirdek User şemasının bir alt kümesidir. Yalnız sağlama
// (provisioning) için gereken çekirdek alanlar modellenir. JSON etiketleri
// SCIM'in camelCase sözleşmesini izler (snake_case değil); bu, şemanın RFC
// 7643 ile tel-uyumlu kalması içindir.
type User struct {
	Schemas    []string `json:"schemas"`
	ID         string   `json:"id,omitempty"`
	ExternalID string   `json:"externalId,omitempty"`
	UserName   string   `json:"userName"`
	Name       Name     `json:"name"`
	Emails     []Email  `json:"emails,omitempty"`
	Active     bool     `json:"active"`
	Meta       Meta     `json:"meta,omitempty"`
}

// Provisioner, bir kimlik sağlayıcısının (IdP) SCIM üzerinden kullanıcı yaşam
// döngüsünü yönettiği arayüzdür: oluşturma, tam değiştirme (PUT), devre dışı
// bırakma (soft-delete) ve okuma.
// Provisioner metotları KİRACI (tenant) kapsamlıdır: her işlem tenantID ile
// sınırlanır; böylece iki kiracı aynı userName'i çakışmadan kullanabilir ve bir
// kiracı diğerinin kullanıcısını göremez/değiştiremez. Boş tenantID "default"
// sayılır (tek-kiracılı kurulumlarla geriye uyumlu).
type Provisioner interface {
	// Create, verilen kiracıda yeni bir kullanıcı sağlar. Aynı kiracıda id ya da
	// userName zaten varsa ErrUserExists döner.
	Create(tenantID string, u User) (User, error)
	// Replace, kiracı+id'deki kullanıcıyı tümüyle değiştirir (SCIM PUT).
	Replace(tenantID, id string, u User) (User, error)
	// Deactivate, kiracı+id'deki kullanıcıyı active=false yapar.
	Deactivate(tenantID, id string) (User, error)
	// Get, kiracı+id'deki kullanıcıyı döndürür.
	Get(tenantID, id string) (User, error)
}

// NormTenant, boş kiracı kimliğini "default"a normalize eder (tek-kiracılı uyum).
func NormTenant(tenantID string) string {
	if tenantID == "" {
		return "default"
	}
	return tenantID
}

// MemProvisioner, Provisioner'ın eşzamanlı-güvenli, bellek-içi bir
// gerçeklemesidir. Test ve tek-düğüm kurulumlar için uygundur.
type MemProvisioner struct {
	mu    sync.RWMutex
	users map[string]User
	// now, meta zaman damgaları için enjekte edilebilir saat (nil ise time.Now).
	now func() time.Time
}

// NewMemProvisioner, boş bir bellek-içi sağlayıcı oluşturur.
func NewMemProvisioner() *MemProvisioner {
	return &MemProvisioner{users: make(map[string]User)}
}

// nowTime, enjekte edilmiş saati veya time.Now'u döndürür.
func (m *MemProvisioner) nowTime() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// normalize, kaydedilen kullanıcının şema ve meta alanlarının tutarlı olmasını
// sağlar.
func (m *MemProvisioner) normalize(u User) User {
	if len(u.Schemas) == 0 {
		u.Schemas = []string{SchemaUser}
	}
	u.Meta.ResourceType = ResourceTypeUser
	return u
}

// key, kiracı+id bileşik anahtarını üretir (kiracı izolasyonu). NUL ayraç id/kiracı
// içinde geçmez.
func memKey(tenantID, id string) string { return NormTenant(tenantID) + "\x00" + id }

// Create, Provisioner arayüzünü gerçekler. Kiracı içinde id VEYA userName çakışırsa
// ErrUserExists (DB'deki UNIQUE(tenant_id, user_name) ile tutarlı).
func (m *MemProvisioner) Create(tenantID string, u User) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if u.ID == "" {
		return User{}, errors.New("iam: SCIM kullanıcısı id gerektirir")
	}
	tid := NormTenant(tenantID)
	if _, ok := m.users[memKey(tid, u.ID)]; ok {
		return User{}, ErrUserExists
	}
	// Aynı kiracıda userName tekliği.
	for k, ex := range m.users {
		if ex.UserName == u.UserName && hasTenantPrefix(k, tid) {
			return User{}, ErrUserExists
		}
	}
	u = m.normalize(u)
	t := m.nowTime()
	u.Meta.Created = t
	u.Meta.LastModified = t
	m.users[memKey(tid, u.ID)] = u
	return u, nil
}

// hasTenantPrefix, bileşik anahtarın verilen kiracıya ait olup olmadığını söyler.
func hasTenantPrefix(key, tenantID string) bool {
	p := tenantID + "\x00"
	return len(key) >= len(p) && key[:len(p)] == p
}

// Replace, Provisioner arayüzünü gerçekler (SCIM PUT; kiracı kapsamlı).
func (m *MemProvisioner) Replace(tenantID, id string, u User) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := memKey(tenantID, id)
	existing, ok := m.users[k]
	if !ok {
		return User{}, ErrUserNotFound
	}
	u = m.normalize(u)
	u.ID = id
	u.Meta.Created = existing.Meta.Created
	u.Meta.LastModified = m.nowTime()
	m.users[k] = u
	return u, nil
}

// Deactivate, Provisioner arayüzünü gerçekler: active=false (soft-delete; kiracı
// kapsamlı). Kalıcı silme kasten desteklenmez — denetim izi korunur.
func (m *MemProvisioner) Deactivate(tenantID, id string) (User, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	k := memKey(tenantID, id)
	u, ok := m.users[k]
	if !ok {
		return User{}, ErrUserNotFound
	}
	u.Active = false
	u.Meta.LastModified = m.nowTime()
	m.users[k] = u
	return u, nil
}

// Get, Provisioner arayüzünü gerçekler (kiracı kapsamlı).
func (m *MemProvisioner) Get(tenantID, id string) (User, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	u, ok := m.users[memKey(tenantID, id)]
	if !ok {
		return User{}, ErrUserNotFound
	}
	return u, nil
}

// SAMLProvider, SAML 2.0 onaylamalarını (assertion) doğrulayan bir sağlayıcının
// arayüzüdür. Tam SAML desteği, imzalı XML belgelerinin XML-dsig ile
// doğrulanmasını (canonicalization/C14N, XML imza çözümleme) gerektirir; bu,
// standart kütüphanenin ötesinde yetenekler (harici bir XML-dsig kütüphanesi)
// ister. Bu nedenle SAML, çekirdek paketin sıfır-bağımlılık kuralını bozmamak
// için kasten bir entegrasyon dikişi olarak bırakılmıştır. Üretim kullanımı
// için bu arayüz, XML-dsig yeteneğine sahip bir yan-hizmet veya derleme
// etiketli bir eklenti tarafından gerçeklenmelidir.
type SAMLProvider interface {
	// ValidateAssertion, ham bir SAML onaylamasını doğrular ve eşlenmiş
	// Claims döndürür.
	ValidateAssertion(assertion []byte) (Claims, error)
}

// NotImplementedSAML, SAMLProvider'ın varsayılan gerçeklemesidir; her çağrıda
// ErrSAMLNotImplemented döner. Gerçek bir sağlayıcı yapılandırılana dek
// güvenli bir varsayılan (fail-closed) sağlar.
type NotImplementedSAML struct{}

// ValidateAssertion, SAMLProvider arayüzünü gerçekler ve her zaman
// ErrSAMLNotImplemented döndürür.
func (NotImplementedSAML) ValidateAssertion(assertion []byte) (Claims, error) {
	return Claims{}, ErrSAMLNotImplemented
}
