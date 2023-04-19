package debug

import (
	"github.com/google/cadvisor/machine"
	"testing"
)

func TestKernelVersion(t *testing.T) {
	t.Log(machine.KernelVersion())
}
