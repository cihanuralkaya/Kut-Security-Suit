// Command rulesimport, IDS imzalarının uç-noktaya uygulanabilir
// alt kümesini KUT yerel tespit kural biçimine (JSON) çevirir. Çıktı,
// KUT_DETECT_RULES_FILE ile C2'ye verilebilir.
//
//	go run ./server/cmd/rulesimport -in ids.rules > detect-rules.json
//	go run ./server/cmd/rulesimport -in ./rules-dir/ -out detect-rules.json
//
// Çok-satırlı .rules dosyaları ('\' satır-devamı) ve dizin (özyinelemesiz
// *.rules) desteklenir. Desteklenmeyen yapılar (paket/akış konumu, byte_test,
// pass eylemi, derlenemeyen pcre) GÜVENLE atlanır ve stderr'e neden yazılır.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"kut.corp/suite/server/internal/detect"
	"kut.corp/suite/server/internal/rulesimport"
)

func main() {
	in := flag.String("in", "", "IDS .rules dosyası veya dizini")
	out := flag.String("out", "", "çıktı JSON dosyası (boş → stdout)")
	flag.Parse()

	if *in == "" {
		log.Fatal("-in zorunlu")
	}
	files, err := gatherFiles(*in)
	if err != nil {
		log.Fatal(err)
	}
	if len(files) == 0 {
		log.Fatal("IDS .rules dosyası bulunamadı")
	}

	var rules []detect.Rule
	totalSkips := 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			log.Printf("okunamadı %s: %v", f, err)
			continue
		}
		rs, skips := rulesimport.ConvertMulti(data)
		rules = append(rules, rs...)
		for _, s := range skips {
			fmt.Fprintf(os.Stderr, "ATLANDI [%s] %s\n", filepath.Base(f), s)
			totalSkips++
		}
	}

	// Çevrilen kuralların motor doğrulamasından geçtiğini teyit et.
	if _, err := detect.LoadRules(strings.NewReader(mustJSON(rules))); err != nil {
		log.Fatalf("çevrilen kurallar motor doğrulamasından geçmedi: %v", err)
	}

	payload := mustJSON(rules)
	if *out == "" {
		fmt.Println(payload)
	} else if err := os.WriteFile(*out, []byte(payload+"\n"), 0o644); err != nil {
		log.Fatal(err)
	}
	fmt.Fprintf(os.Stderr, "%d kural çevrildi, %d satır atlandı.\n", len(rules), totalSkips)
}

func gatherFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{path}, nil
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var files []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if strings.HasSuffix(strings.ToLower(e.Name()), ".rules") {
			files = append(files, filepath.Join(path, e.Name()))
		}
	}
	return files, nil
}

func mustJSON(rules []detect.Rule) string {
	b, err := json.MarshalIndent(rules, "", "  ")
	if err != nil {
		log.Fatal(err)
	}
	return string(b)
}
