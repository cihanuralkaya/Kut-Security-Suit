package memstore

import (
	"testing"

	"kut.corp/suite/cmdenvelope"
	kutv1 "kut.corp/suite/gen/kut/v1"
)

// Bellek deposu da DB deposuyla AYNI tablo-türevli eşlemeyi kullanır (sürüklenme koruması).
func TestCommandTypeToProtoFollowsTable(t *testing.T) {
	for _, s := range cmdenvelope.All() {
		got := commandTypeToProto(s.Name)
		if got == kutv1.Command_COMMAND_TYPE_UNSPECIFIED || got.String() != s.ProtoEnum {
			t.Errorf("%s -> %s, tablo %s", s.Name, got, s.ProtoEnum)
		}
	}
	for _, bad := range []string{"", "NOPE", "quarantine", "COMMAND_TYPE_WIPE"} {
		if got := commandTypeToProto(bad); got != kutv1.Command_COMMAND_TYPE_UNSPECIFIED {
			t.Errorf("kayıtsız %q -> %s (UNSPECIFIED beklenirdi)", bad, got)
		}
	}
}
