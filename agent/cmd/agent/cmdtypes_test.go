package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"reflect"
	"sort"
	"strings"
	"testing"

	"kut.corp/suite/cmdenvelope"
	kutv1 "kut.corp/suite/gen/kut/v1"
)

// agentUnhandled, tabloda KAYITLI ama handleCommands anahtarında (bilinçli olarak) dalı
// OLMAYAN tiplerdir. Bir tip burada duruyorsa ajan onu yürütmez; bir dal eklendiğinde bu
// liste güncellenmelidir (test aksi halde kırılır) — sessiz sürüklenme olmaz.
var agentUnhandled = map[string]string{
	cmdenvelope.TypeUninstall:          "yönetici giriş noktası yok; kaldırma akışı ayrı (sonraki sürüm)",
	cmdenvelope.TypeCollectDiagnostics: "ajan tarafı uygulaması henüz yok (varsayılan dal boş)",
}

// handleCommandsCases, main.go içindeki handleCommands fonksiyonunun komut-tipi
// anahtarındaki `kutv1.Command_COMMAND_TYPE_*` dal adlarını döner.
func handleCommandsCases(t *testing.T) map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "main.go", nil, 0)
	if err != nil {
		t.Fatalf("main.go ayrıştırılamadı: %v", err)
	}
	out := map[string]bool{}
	found := false
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "handleCommands" {
			continue
		}
		found = true
		ast.Inspect(fn, func(n ast.Node) bool {
			cc, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, e := range cc.List {
				if sel, ok := e.(*ast.SelectorExpr); ok && strings.HasPrefix(sel.Sel.Name, "Command_COMMAND_TYPE_") {
					out[strings.TrimPrefix(sel.Sel.Name, "Command_")] = true
				}
			}
			return true
		})
	}
	if !found {
		t.Fatal("handleCommands bulunamadı (yeniden adlandırıldı mı? sürüklenme koruması güncellenmeli)")
	}
	return out
}

// TestAgentSwitchDrift: handleCommands anahtarı ile tablo iki yönde uyumlu olmalı.
func TestAgentSwitchDrift(t *testing.T) {
	cases := handleCommandsCases(t)
	// Anahtardaki her dal tabloda kayıtlı olmalı.
	for protoName := range cases {
		if _, ok := cmdenvelope.LookupProto(protoName); !ok {
			t.Errorf("ajan anahtarı %s işliyor ama tipi tabloda YOK", protoName)
		}
	}
	// Tablodaki her tip ya anahtarda ya da gerekçeli agentUnhandled listesinde olmalı.
	for _, s := range cmdenvelope.All() {
		_, handled := cases[s.ProtoEnum]
		reason, unhandled := agentUnhandled[s.Name]
		switch {
		case !handled && !unhandled:
			t.Errorf("tablo tipi %s ajan anahtarında YOK ve agentUnhandled'da gerekçelendirilmemiş", s.Name)
		case handled && unhandled:
			t.Errorf("%s ajan anahtarında VAR ama agentUnhandled'da duruyor (%s) — listeyi güncelleyin", s.Name, reason)
		}
	}
	for name := range agentUnhandled {
		if !cmdenvelope.Known(name) {
			t.Errorf("agentUnhandled bilinmeyen tip içeriyor: %s", name)
		}
	}
}

// TestAgentProtectedSetMatchesServerTable: ajanın korumalı kümesi, sunucunun kullandığı aynı
// tablo kümesidir; COLLECT_DIAGNOSTICS dâhil, UNSPECIFIED/kayıtsız fail-closed korumalı.
func TestAgentProtectedSetMatchesServerTable(t *testing.T) {
	var agentSet []string
	for name, num := range kutv1.Command_CommandType_value {
		typ := kutv1.Command_CommandType(num)
		if typ == kutv1.Command_COMMAND_TYPE_UNSPECIFIED {
			if _, ok := commandSpec(typ); ok {
				t.Error("UNSPECIFIED tabloda kayıtlı olmamalı")
			}
			if !commandProtected(typ) {
				t.Error("UNSPECIFIED fail-closed korumalı sayılmalı")
			}
			continue
		}
		spec, ok := commandSpec(typ)
		if !ok {
			t.Errorf("%s tabloda yok", name)
			continue
		}
		if commandProtected(typ) != spec.Protected {
			t.Errorf("%s: ajan korumalılığı tabloyla çelişiyor", name)
		}
		if commandProtected(typ) {
			agentSet = append(agentSet, spec.Name)
		}
	}
	sort.Strings(agentSet)
	if want := cmdenvelope.ProtectedNames(); !reflect.DeepEqual(agentSet, want) {
		t.Fatalf("ajan korumalı kümesi sunucu tablosundan farklı:\n agent  %v\n server %v", agentSet, want)
	}
	if !commandProtected(kutv1.Command_COMMAND_TYPE_COLLECT_DIAGNOSTICS) {
		t.Error("COLLECT_DIAGNOSTICS korumalı olmalı (muafiyet yok)")
	}
	if !commandProtected(kutv1.Command_CommandType(9999)) {
		t.Error("tanınmayan proto değeri fail-closed korumalı olmalı")
	}
}
