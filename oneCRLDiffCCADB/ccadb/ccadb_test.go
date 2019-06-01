package ccadb

import (
	"testing"
)

func TestDupe(t *testing.T) {
	certs, err := Retrieve()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(certs)
}
