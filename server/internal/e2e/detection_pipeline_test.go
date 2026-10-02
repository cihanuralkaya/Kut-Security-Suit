// Package e2e: ham Windows Olay Günlüğü alımından tespit tekniğine kadar
// GERÇEKÇİ tespit hattının uçtan-uca kanıtı.
//
// Birim testleri her paketi ayrı doğrular (logingest kategori eşlemesi, detect
// kural eşleşmesi). Bu test onların BİRLİKTE çalıştığını kanıtlar: logingest'in
// ürettiği olay (kategori + komut-satırı taşıyan mesaj), detect motorunun
// kategori-bağımsız IOC kurallarıyla doğru ATT&CK tekniğine eşleşir. Böylece
// logingest çıktı biçimi ile tespit desenleri arasındaki sessiz sapma (format
// drift) — ör. mesaj biçimi değişip komut-satırının kaybolması — CI'da yakalanır.
//
// NOT (hat): agent_handler'da detect motoru eşleşirse (len(dets)>0) alarm kuralın
// tekniğiyle üretilir; mitre.Classify YALNIZ hiçbir kural eşleşmediğinde yedek
// zenginleştirmedir. Bu yüzden burada birincil (detect) yol doğrulanır.
package e2e

import (
	"testing"
	"time"

	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/logingest"
)

func TestDetectionPipelineFromWinlog(t *testing.T) {
	now := time.Now()
	eng := detect.NewEngine(detect.DefaultRules()) // ÜRETİM kural kataloğu

	cases := []struct {
		name     string
		winJSON  string
		wantCat  string // logingest'in atadığı kategori (kaynak→kategori eşlemesi)
		wantTech string // detect motorunun üretmesi gereken teknik
	}{
		{
			name:     "Windows 4688 sürec olusturma — WMI komut satiri (PROCESS)",
			winJSON:  `{"winlog":{"event_id":4688,"channel":"Security","computer_name":"WS-01"},"message":"A new process has been created. Process Command Line: wmic process call create calc.exe"}`,
			wantCat:  "PROCESS",
			wantTech: "T1047",
		},
		{
			name:     "Sysmon EID 8 — enjeksiyon (SECURITY), kategori-bagimsiz kural eslesir",
			winJSON:  `{"winlog":{"event_id":8,"channel":"Microsoft-Windows-Sysmon/Operational","computer_name":"WS-01"},"message":"target image explorer.exe"}`,
			wantCat:  "SECURITY",
			wantTech: "T1055",
		},
		{
			name:     "Windows 4688 — guvenlik duvari devre disi komutu (PROCESS)",
			winJSON:  `{"winlog":{"event_id":4688,"channel":"Security","computer_name":"WS-01"},"message":"A new process has been created. Process Command Line: netsh advfirewall set allprofiles state off"}`,
			wantCat:  "PROCESS",
			wantTech: "T1562",
		},
	}

	for _, c := range cases {
		recs, err := logingest.NormalizeWinEvent([]byte(c.winJSON), now)
		if err != nil || len(recs) != 1 {
			t.Fatalf("%s: normalize hata: %v (%d kayit)", c.name, err, len(recs))
		}
		ev := recs[0].Event
		if ev.Category != c.wantCat {
			t.Errorf("%s: kategori %q bekleniyordu, gelen %q", c.name, c.wantCat, ev.Category)
		}
		found := false
		for _, d := range eng.Evaluate(ev) {
			if d.Technique.ID == c.wantTech {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: detect %s uretmeliydi; olay=%q msg=%q", c.name, c.wantTech, ev.Category, ev.Message)
		}
	}
}
