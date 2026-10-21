package db

import (
	"testing"

	"kut.corp/suite/cmdenvelope"
	kutv1 "kut.corp/suite/gen/kut/v1"
)

// DB gerektirmez: kuyruk türü adı -> proto enum eşlemesi PAYLAŞILAN komut tablosundan gelir;
// tablodaki her tip tanınır ve doğru proto değerine gider, kayıtsız ad UNSPECIFIED döner.
func TestCommandTypeToProtoFollowsTable(t *testing.T) {
	for _, s := range cmdenvelope.All() {
		got := commandTypeToProto(s.Name)
		if got == kutv1.Command_COMMAND_TYPE_UNSPECIFIED {
			t.Errorf("%s UNSPECIFIED'a düştü", s.Name)
			continue
		}
		if got.String() != s.ProtoEnum {
			t.Errorf("%s -> %s, tablo %s", s.Name, got, s.ProtoEnum)
		}
	}
	for _, bad := range []string{"", "NOPE", "quarantine", "COMMAND_TYPE_WIPE"} {
		if got := commandTypeToProto(bad); got != kutv1.Command_COMMAND_TYPE_UNSPECIFIED {
			t.Errorf("kayıtsız %q -> %s (UNSPECIFIED beklenirdi)", bad, got)
		}
	}
}
