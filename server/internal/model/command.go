package model

// CommandOutcome, ajanın heartbeat'te bildirdiği tek bir komut YÜRÜTME sonucudur
// (server-içi, proto'dan bağımsız biçim). Sunucu bununla desired→effective cihaz durum
// geçişini yapar (ör. QUARANTINE OK → cihaz gerçekten izole). ACK (teslim) ile SUCCESS
// (uygulandı) burada ayrışır.
type CommandOutcome struct {
	CommandID string
	Type      string // komut tipi: "QUARANTINE" / "UNQUARANTINE" / ... (kuyruk türüyle aynı)
	OK        bool   // true=SUCCEEDED, false=FAILED
}
