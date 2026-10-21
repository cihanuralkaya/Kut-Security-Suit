package db

// validUUID, s'in kanonik 8-4-4-4-12 hex UUID biçiminde olup olmadığını döner. İstemciden
// gelen id'ler `= $1::uuid` karşılaştırmasına girmeden önce doğrulanır: geçersiz bir id
// 22P02 (500) yerine "bulunamadı" gibi ele alınır (fail-closed, varlık sızdırmaz).
func validUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
				return false
			}
		}
	}
	return true
}
