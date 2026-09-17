package iam

import (
	"encoding/json"
	"sync"
	"testing"
	"time"
)

func sampleUser() User {
	return User{
		Schemas:    []string{SchemaUser},
		ID:         "u-1",
		ExternalID: "ext-42",
		UserName:   "alice@kut.corp",
		Name:       Name{GivenName: "Alice", FamilyName: "Analyst"},
		Emails: []Email{
			{Value: "alice@kut.corp", Type: "work", Primary: true},
		},
		Active: true,
	}
}

func TestUserJSONRoundTrip(t *testing.T) {
	u := sampleUser()
	data, err := json.Marshal(u)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	// SCIM camelCase etiketlerini doğrula.
	var asMap map[string]any
	if err := json.Unmarshal(data, &asMap); err != nil {
		t.Fatalf("map unmarshal: %v", err)
	}
	for _, key := range []string{"schemas", "id", "externalId", "userName", "name", "emails", "active"} {
		if _, ok := asMap[key]; !ok {
			t.Fatalf("missing JSON key %q in %s", key, data)
		}
	}

	var back User
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.UserName != u.UserName || back.Name.GivenName != "Alice" ||
		back.Name.FamilyName != "Analyst" || back.ExternalID != "ext-42" ||
		len(back.Emails) != 1 || back.Emails[0].Value != "alice@kut.corp" ||
		!back.Emails[0].Primary || !back.Active {
		t.Fatalf("round-trip mismatch: %+v", back)
	}
}

func TestMemProvisionerLifecycle(t *testing.T) {
	m := NewMemProvisioner()
	fixed := time.Unix(1_700_000_000, 0)
	m.now = func() time.Time { return fixed }

	created, err := m.Create("t1", sampleUser())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if created.Meta.ResourceType != ResourceTypeUser {
		t.Fatalf("meta.resourceType = %q", created.Meta.ResourceType)
	}
	if !created.Meta.Created.Equal(fixed) {
		t.Fatalf("meta.created = %v", created.Meta.Created)
	}

	// Duplicate.
	if _, err := m.Create("t1", sampleUser()); err != ErrUserExists {
		t.Fatalf("duplicate Create err = %v, want ErrUserExists", err)
	}

	// Get.
	got, err := m.Get("t1", "u-1")
	if err != nil || got.UserName != "alice@kut.corp" {
		t.Fatalf("Get = %+v, %v", got, err)
	}

	// Replace.
	upd := sampleUser()
	upd.Name.GivenName = "Alicia"
	replaced, err := m.Replace("t1", "u-1", upd)
	if err != nil {
		t.Fatalf("Replace: %v", err)
	}
	if replaced.Name.GivenName != "Alicia" {
		t.Fatalf("Replace name = %q", replaced.Name.GivenName)
	}
	if !replaced.Meta.Created.Equal(fixed) {
		t.Fatalf("Replace should preserve created: %v", replaced.Meta.Created)
	}

	// Deactivate.
	deact, err := m.Deactivate("t1", "u-1")
	if err != nil {
		t.Fatalf("Deactivate: %v", err)
	}
	if deact.Active {
		t.Fatal("Deactivate should set active=false")
	}

	// Missing id errors.
	if _, err := m.Get("t1", "missing"); err != ErrUserNotFound {
		t.Fatalf("Get missing err = %v", err)
	}
	if _, err := m.Replace("t1", "missing", sampleUser()); err != ErrUserNotFound {
		t.Fatalf("Replace missing err = %v", err)
	}
	if _, err := m.Deactivate("t1", "missing"); err != ErrUserNotFound {
		t.Fatalf("Deactivate missing err = %v", err)
	}
}

func TestMemProvisionerCreateNormalizesSchema(t *testing.T) {
	m := NewMemProvisioner()
	u := sampleUser()
	u.Schemas = nil
	created, err := m.Create("t1", u)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(created.Schemas) != 1 || created.Schemas[0] != SchemaUser {
		t.Fatalf("schema not normalized: %v", created.Schemas)
	}
}

func TestMemProvisionerConcurrent(t *testing.T) {
	m := NewMemProvisioner()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			u := sampleUser()
			u.ID = "u-" + string(rune('A'+n%26)) + string(rune('0'+n/26))
			_, _ = m.Create("t1", u)
			_, _ = m.Get("t1", u.ID)
			_, _ = m.Deactivate("t1", u.ID)
		}(i)
	}
	wg.Wait()
}

// TestMemProvisionerTenantIsolation, KİRACI izolasyonunu doğrular: iki farklı kiracı
// AYNI userName'i çakışmadan kullanabilir; aynı kiracıda tekrar → ErrUserExists; bir
// kiracı diğerinin kullanıcısını göremez/değiştiremez.
func TestMemProvisionerTenantIsolation(t *testing.T) {
	m := NewMemProvisioner()
	uA := sampleUser()
	uA.ID = "id-A"
	uB := sampleUser()
	uB.ID = "id-B" // farklı id ama AYNI userName

	if _, err := m.Create("tenant-A", uA); err != nil {
		t.Fatalf("tenant-A create: %v", err)
	}
	// Farklı kiracı, aynı userName → başarılı olmalı (global çakışma yok).
	if _, err := m.Create("tenant-B", uB); err != nil {
		t.Fatalf("farklı kiracı aynı userName başarılı olmalı: %v", err)
	}
	// Aynı kiracıda aynı userName (farklı id) → ErrUserExists.
	dup := sampleUser()
	dup.ID = "id-A2"
	if _, err := m.Create("tenant-A", dup); err != ErrUserExists {
		t.Fatalf("aynı kiracıda userName tekrarı ErrUserExists olmalı: %v", err)
	}
	// Kiracı-A, tenant-B'nin kullanıcısını GÖREMEZ.
	if _, err := m.Get("tenant-A", "id-B"); err != ErrUserNotFound {
		t.Fatalf("kiracı çapraz Get ErrUserNotFound olmalı: %v", err)
	}
	// Kiracı-A kendi kullanıcısını görür.
	if _, err := m.Get("tenant-A", "id-A"); err != nil {
		t.Fatalf("kiracı kendi kullanıcısını görmeli: %v", err)
	}
	// Deactivate de kiracı-kapsamlı: tenant-B, tenant-A'nın kullanıcısını devre dışı bırakamaz.
	if _, err := m.Deactivate("tenant-B", "id-A"); err != ErrUserNotFound {
		t.Fatalf("kiracı çapraz Deactivate ErrUserNotFound olmalı: %v", err)
	}
	// Boş kiracı "default"a normalize edilir (tek-kiracılı uyum).
	if NormTenant("") != "default" {
		t.Fatal("boş kiracı 'default' olmalı")
	}
}

func TestNotImplementedSAML(t *testing.T) {
	var p SAMLProvider = NotImplementedSAML{}
	if _, err := p.ValidateAssertion([]byte("<saml/>")); err != ErrSAMLNotImplemented {
		t.Fatalf("want ErrSAMLNotImplemented, got %v", err)
	}
}
