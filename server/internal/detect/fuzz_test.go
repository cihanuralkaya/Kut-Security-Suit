package detect

import (
	"strings"
	"testing"

	"kut.corp/suite/server/internal/model"
)

func FuzzLoadRules(f *testing.F) {
	f.Add(`[{"id":"a","name":"n","severity":"HIGH","contains":["x"]}]`)
	f.Add(`[{"id":"b","name":"m","severity":"LOW","message_regex":"("}]`)
	f.Add(`garbage`)
	f.Fuzz(func(t *testing.T, s string) {
		_, _ = LoadRules(strings.NewReader(s)) // panik olmamalı
	})
}

// FuzzEvaluate, kural DEĞERLENDİRME yolunu (matchSequence/Absent/within + MPM
// ön-filtre — dilim-indeksleme içeren yeni mantık) rastgele kural+mesaj çiftleriyle
// panik açısından tarar. LoadRules geçerli döndüren kural setleri motora verilip
// fuzz'lanan mesaja karşı değerlendirilir.
func FuzzEvaluate(f *testing.F) {
	f.Add(`[{"id":"a","name":"n","severity":"HIGH","sequence":["ab","cd"],"within_bytes":5}]`, "ab xx cd")
	f.Add(`[{"id":"b","name":"m","severity":"LOW","contains":["x"],"absent":["y"]}]`, "x here")
	f.Add(`[{"id":"c","name":"p","severity":"HIGH","message_regex":"a.*b"}]`, "aXb")
	f.Add(`garbage`, "")
	f.Fuzz(func(t *testing.T, rulesJSON, msg string) {
		rules, err := LoadRules(strings.NewReader(rulesJSON))
		if err != nil {
			return // geçersiz kural seti — değerlendirme yolunu sürmeyiz
		}
		e := NewEngine(rules)
		_ = e.Evaluate(model.Event{Message: msg, Severity: "HIGH", Category: "X"}) // panik olmamalı
	})
}
