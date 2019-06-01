package oneCRL

import (
	"testing"
)

func TestGet(t *testing.T) {
	r, err := Retrieve()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(r)
}
