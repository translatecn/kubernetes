package debug

import (
	"encoding/json"
	"github.com/google/cadvisor/machine"
	"testing"
	"time"
)

func TestKernelVersion(t *testing.T) {
	t.Log(machine.KernelVersion())
}
func Str(a []byte, err error) string {
	return string(a)
}
func TestMarshalTime(t *testing.T) {
	_t := time.Now()
	t.Log(Str(json.Marshal(_t.UTC())))
	t.Log(Str(json.Marshal(_t.UTC().Format(time.RFC3339))))
}
