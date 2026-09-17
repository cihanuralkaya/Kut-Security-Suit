// Command mkclient, uç cihazlar için TEK DOSYA, kendi kendine yeten bir istemci
// kurulum betiği üretir (Windows PowerShell .ps1 veya Linux .sh).
//
// İki mod:
//   - Benzersiz setup: -token verilir → kayıt token'ı betiğe gömülür; kullanıcı
//     yalnız çalıştırır, otomatik kaydolur.
//   - Paylaşımlı setup: -token boş → betik çalışırken kullanıcıdan kayıt kodunu
//     ister (tek installer birçok cihaza dağıtılır).
//
// Ajan ikilisi -agent ile verilirse base64 olarak gömülür (gerçek tek-dosya
// setup). Verilmezse betik, yanındaki agent(.exe) dosyasını bekler.
//
// Örnek:
//
//	mkclient -os windows -server c2.sirket.local -ca dev-certs/ca.crt \
//	         -agent dist/windows-amd64/agent.exe -token ABC123 -out setup.ps1
package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/template"
)

type params struct {
	Server     string
	EnrollAddr string
	AgentAddr  string
	ServerName string
	Heartbeat  string
	SafeMode   string
	Token      string
	CAPEM      string
	AgentB64   string
	Embedded   bool // token gömülü mü (benzersiz setup)
}

func main() {
	osFlag := flag.String("os", "", "hedef OS: windows | linux (zorunlu)")
	server := flag.String("server", "", "C2 sunucu adresi/host (zorunlu)")
	enrollPort := flag.Int("enroll-port", 8444, "enrollment portu")
	agentPort := flag.Int("agent-port", 8443, "agent (mTLS) portu")
	name := flag.String("name", "kut-c2", "sunucu TLS adı (SAN)")
	caPath := flag.String("ca", "", "CA sertifikası (PEM) yolu (zorunlu)")
	agentPath := flag.String("agent", "", "ajan ikilisi (gömülecek); boşsa betik yanındaki dosyayı bekler")
	token := flag.String("token", "", "kayıt token'ı; verilirse gömülür (benzersiz setup), boşsa kod girişi istenir")
	heartbeat := flag.String("heartbeat", "30s", "heartbeat aralığı")
	safeMode := flag.Bool("safe-mode", false, "KUT_SAFE_MODE=1 (karantina gerçek ağ değişikliği yapmaz)")
	out := flag.String("out", "", "çıktı betiği yolu (varsayılan: kut-agent-setup.ps1/.sh)")
	flag.Parse()

	if *osFlag != "windows" && *osFlag != "linux" {
		fatal("-os windows|linux olmalı")
	}
	if *server == "" || *caPath == "" {
		fatal("-server ve -ca zorunludur")
	}

	caPEM, err := os.ReadFile(*caPath)
	if err != nil {
		fatal("CA okunamadı: %v", err)
	}

	p := params{
		Server:     *server,
		EnrollAddr: fmt.Sprintf("%s:%d", *server, *enrollPort),
		AgentAddr:  fmt.Sprintf("%s:%d", *server, *agentPort),
		ServerName: *name,
		Heartbeat:  *heartbeat,
		Token:      *token,
		CAPEM:      strings.TrimRight(string(caPEM), "\n"),
		Embedded:   *token != "",
	}
	if *safeMode {
		p.SafeMode = "1"
	}
	if *agentPath != "" {
		b, err := os.ReadFile(*agentPath)
		if err != nil {
			fatal("ajan ikilisi okunamadı: %v", err)
		}
		p.AgentB64 = base64.StdEncoding.EncodeToString(b)
	}

	tmpl := winTemplate
	outPath := "kut-agent-setup.ps1"
	if *osFlag == "linux" {
		tmpl = linuxTemplate
		outPath = "kut-agent-setup.sh"
	}
	if *out != "" {
		outPath = *out
	}

	t := template.Must(template.New("installer").Parse(tmpl))
	f, err := os.Create(outPath)
	if err != nil {
		fatal("çıktı oluşturulamadı: %v", err)
	}
	defer f.Close()
	if err := t.Execute(f, p); err != nil {
		fatal("şablon işlenemedi: %v", err)
	}
	if *osFlag == "linux" {
		_ = os.Chmod(outPath, 0o755)
	}

	mode := "PAYLAŞIMLI (kod girişli)"
	if p.Embedded {
		mode = "BENZERSİZ (token gömülü)"
	}
	bundled := "hayır (agent yanında beklenir)"
	if p.AgentB64 != "" {
		bundled = "evet (base64 gömülü)"
	}
	fmt.Printf("Üretildi: %s\n  Mod: %s\n  Ajan gömülü: %s\n  Sunucu: %s (enroll %s, agent %s)\n",
		outPath, mode, bundled, p.Server, p.EnrollAddr, p.AgentAddr)
}

func fatal(f string, a ...any) {
	fmt.Fprintf(os.Stderr, "mkclient: "+f+"\n", a...)
	os.Exit(1)
}

// --- Windows PowerShell şablonu ---
const winTemplate = `#Requires -RunAsAdministrator
# KUT Agent kurulum betiği (otomatik üretildi — mkclient).
$ErrorActionPreference = "Stop"

$EnrollAddr = "{{.EnrollAddr}}"
$AgentAddr  = "{{.AgentAddr}}"
$ServerName = "{{.ServerName}}"
$Heartbeat  = "{{.Heartbeat}}"
$SafeMode   = "{{.SafeMode}}"
$Token      = "{{.Token}}"
$InstallDir = "$env:ProgramFiles\KUT Agent"
$DataDir    = "$InstallDir\data"

if ([string]::IsNullOrEmpty($Token)) {
    $Token = Read-Host "Kayıt kodunu (enrollment token) girin"
}
if ([string]::IsNullOrEmpty($Token)) { throw "Kayıt token'ı gerekli." }

New-Item -ItemType Directory -Force -Path $InstallDir, $DataDir | Out-Null

# CA güven çıpası
$CA = @'
{{.CAPEM}}
'@
Set-Content -Path "$InstallDir\ca.pem" -Value $CA -Encoding ascii
{{if .AgentB64}}
# Ajan ikilisi (base64 gömülü)
$B64 = @'
{{.AgentB64}}
'@
[System.IO.File]::WriteAllBytes("$InstallDir\agent.exe", [System.Convert]::FromBase64String($B64))
{{else}}
Copy-Item -Path (Join-Path $PSScriptRoot "agent.exe") -Destination "$InstallDir\agent.exe" -Force
{{end}}
# Ajanı çalıştıran ortam sarmalayıcı (.cmd)
$Wrapper = @"
@echo off
set KUT_ENROLL_ADDR=$EnrollAddr
set KUT_AGENT_ADDR=$AgentAddr
set KUT_SERVER_NAME=$ServerName
set KUT_CA_PEM=$InstallDir\ca.pem
set KUT_AGENT_DATA=$DataDir
set KUT_HEARTBEAT_INTERVAL=$Heartbeat
set KUT_SAFE_MODE=$SafeMode
set KUT_ENROLL_TOKEN=$Token
"$InstallDir\agent.exe"
"@
Set-Content -Path "$InstallDir\run-agent.cmd" -Value $Wrapper -Encoding ascii

# Açılışta SYSTEM olarak çalışacak zamanlanmış görev
$Action    = New-ScheduledTaskAction -Execute "$InstallDir\run-agent.cmd"
$Trigger   = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
Register-ScheduledTask -TaskName "KUT Agent" -Action $Action -Trigger $Trigger -Principal $Principal -Force | Out-Null
Start-ScheduledTask -TaskName "KUT Agent"

Write-Host "KUT Agent kuruldu ve başlatıldı ($InstallDir)."
`

// --- Linux bash şablonu ---
const linuxTemplate = `#!/usr/bin/env bash
# KUT Agent kurulum betiği (otomatik üretildi — mkclient).
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "root olarak çalıştırın (sudo)." >&2; exit 1; }

ENROLL_ADDR="{{.EnrollAddr}}"
AGENT_ADDR="{{.AgentAddr}}"
SERVER_NAME="{{.ServerName}}"
HEARTBEAT="{{.Heartbeat}}"
SAFE_MODE="{{.SafeMode}}"
TOKEN="{{.Token}}"
INSTALL_DIR="/opt/kut-agent"
DATA_DIR="/var/lib/kut-agent"
CONF_DIR="/etc/kut-agent"

if [ -z "$TOKEN" ]; then
  read -r -p "Kayıt kodunu (enrollment token) girin: " TOKEN
fi
[ -n "$TOKEN" ] || { echo "Kayıt token'ı gerekli." >&2; exit 1; }

mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$CONF_DIR"

cat > "$CONF_DIR/ca.pem" <<'CAEOF'
{{.CAPEM}}
CAEOF
{{if .AgentB64}}
# Ajan ikilisi (base64 gömülü)
base64 -d > "$INSTALL_DIR/agent" <<'BINEOF'
{{.AgentB64}}
BINEOF
chmod +x "$INSTALL_DIR/agent"
{{else}}
install -m 0755 "$(dirname "$0")/agent" "$INSTALL_DIR/agent"
{{end}}
cat > "$CONF_DIR/agent.env" <<ENVEOF
KUT_ENROLL_ADDR=$ENROLL_ADDR
KUT_AGENT_ADDR=$AGENT_ADDR
KUT_SERVER_NAME=$SERVER_NAME
KUT_CA_PEM=$CONF_DIR/ca.pem
KUT_AGENT_DATA=$DATA_DIR
KUT_HEARTBEAT_INTERVAL=$HEARTBEAT
KUT_SAFE_MODE=$SAFE_MODE
KUT_ENROLL_TOKEN=$TOKEN
ENVEOF
chmod 600 "$CONF_DIR/agent.env"

cat > /etc/systemd/system/kut-agent.service <<UNITEOF
[Unit]
Description=KUT Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=$CONF_DIR/agent.env
ExecStart=$INSTALL_DIR/agent
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
UNITEOF

systemctl daemon-reload
systemctl enable --now kut-agent.service
echo "KUT Agent kuruldu ve başlatıldı (systemctl status kut-agent)."
`
