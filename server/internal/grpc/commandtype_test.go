package grpc

import (
	"testing"

	"kut.corp/suite/cmdenvelope"
	kutv1 "kut.corp/suite/gen/kut/v1"
)

// commandTypeName yalnız effective-state ile ilgili tipleri adlandırır; döndürdüğü her ad
// paylaşılan tabloda kayıtlı olmalı ve AYNI proto tipine geri çevrilmelidir.
func TestCommandTypeNameAgreesWithTable(t *testing.T) {
	named := 0
	for name, num := range kutv1.Command_CommandType_value {
		typ := kutv1.Command_CommandType(num)
		got := commandTypeName(typ)
		if got == "" {
			continue
		}
		named++
		spec, ok := cmdenvelope.Lookup(got)
		if !ok {
			t.Errorf("%s -> %q tabloda kayıtlı değil", name, got)
			continue
		}
		if spec.ProtoEnum != name {
			t.Errorf("commandTypeName(%s) = %q ama tablo bu ad için %s diyor", name, got, spec.ProtoEnum)
		}
	}
	if named == 0 {
		t.Fatal("commandTypeName hiçbir tip adlandırmadı")
	}
	if got := commandTypeName(kutv1.Command_COMMAND_TYPE_UNSPECIFIED); got != "" {
		t.Errorf("UNSPECIFIED adlandırılmamalı: %q", got)
	}
}
