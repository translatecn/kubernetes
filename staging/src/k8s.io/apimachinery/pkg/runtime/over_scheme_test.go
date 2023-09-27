package runtime

import (
	"fmt"
	"testing"
)

func TestStrict(t *testing.T) {
	a := map[string]interface{}{
		"a": 1,
	}
	x := &A{}
	fmt.Println(DefaultUnstructuredConverter.FromUnstructured(a, x))
	fmt.Println(DefaultUnstructuredConverter.FromUnstructuredWithValidation(a, x, true))
	fmt.Println(x)
}

type A struct {
	B string
}
