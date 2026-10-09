package adminapi

import "testing"

func TestParseIndicator(t *testing.T) {
	cases := []struct {
		in            string
		kind, id, rel string
		ok            bool
	}{
		{"ip|1.2.3.4|connected", "ip", "1.2.3.4", "connected", true},
		{" IP | 1.2.3.4 | Connected ", "ip", "1.2.3.4", "connected", true}, // trim + lowercase kind/rel
		{"domain|evil.example|resolved", "domain", "evil.example", "resolved", true},
		{"ip|1.2.3.4", "", "", "", false},         // eksik parça
		{"ip||connected", "", "", "", false},      // boş id
		{"|1.2.3.4|connected", "", "", "", false}, // boş kind
		{"", "", "", "", false},
		{"a|b|c|d", "", "", "", false}, // fazla parça
	}
	for _, c := range cases {
		k, id, rel, ok := parseIndicator(c.in)
		if ok != c.ok || k != c.kind || id != c.id || rel != c.rel {
			t.Errorf("parseIndicator(%q) → (%q,%q,%q,%v) beklenen (%q,%q,%q,%v)",
				c.in, k, id, rel, ok, c.kind, c.id, c.rel, c.ok)
		}
	}
}
