package commandplane

import (
	"reflect"
	"sort"
	"testing"

	"kut.corp/suite/cmdenvelope"
)

// allTypeConsts, bu paketin dışa açtığı tüm CommandType sabitleridir. Tabloya yeni tip
// eklendiğinde buraya da eklenmeden TestTypeConstsCoverTable kırılır.
var allTypeConsts = []CommandType{
	TypeQuarantine, TypeUnquarantine, TypeLock, TypeRestart, TypeWipe,
	TypeRunSignedScript, TypeCollectFile, TypeCollectDiagnostics, TypeUninstall,
}

func TestTypeConstsCoverTable(t *testing.T) {
	var got []string
	for _, c := range allTypeConsts {
		got = append(got, string(c))
	}
	sort.Strings(got)
	if want := cmdenvelope.Names(); !reflect.DeepEqual(got, want) {
		t.Fatalf("CommandType sabitleri tabloyla ayrıştı:\n consts %v\n table  %v", got, want)
	}
}

// tablodaki her tip için Validate başarılı + Spec var; kayıtsız tip reddedilir.
func TestValidateFollowsSharedTable(t *testing.T) {
	for _, s := range cmdenvelope.All() {
		r := CommandRequest{DeviceID: "d", Type: CommandType(s.Name), IssuedBy: "u"}
		if err := r.Validate(); err != nil {
			t.Errorf("%s: Validate reddetti: %v", s.Name, err)
		}
		if sp, ok := Spec(CommandType(s.Name)); !ok || sp.Name != s.Name {
			t.Errorf("%s: Spec tutarsız", s.Name)
		}
	}
	for _, bad := range []CommandType{"SELFDESTRUCT", "quarantine", "COMMAND_TYPE_WIPE", " WIPE"} {
		r := CommandRequest{DeviceID: "d", Type: bad, IssuedBy: "u"}
		if err := r.Validate(); err == nil {
			t.Errorf("kayıtsız tip %q kabul edildi (fail-closed ihlali)", bad)
		}
		if _, ok := Spec(bad); ok {
			t.Errorf("Spec(%q) bulundu", bad)
		}
	}
}

// Ajan/sunucu uyumu (sunucu yarısı): düzlemin imzalamayı kabul ettiği HER tip, ajan tarafında
// da korumalı (imzasız reddedilen) kümededir — imzalanan ama korumasız tip olamaz.
func TestEveryPlaneAcceptedTypeIsProtected(t *testing.T) {
	for _, s := range cmdenvelope.All() {
		r := CommandRequest{DeviceID: "d", Type: CommandType(s.Name), IssuedBy: "u"}
		if r.Validate() == nil && !cmdenvelope.Protected(s.Name) {
			t.Errorf("%s düzlemden geçiyor ama korumasız", s.Name)
		}
	}
}
