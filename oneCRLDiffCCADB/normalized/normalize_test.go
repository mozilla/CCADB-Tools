package normalized

import (
	"github.com/mozilla/CCADB-Tools/oneCRLDiffCCADB/ccadb"
	"github.com/mozilla/CCADB-Tools/oneCRLDiffCCADB/oneCRL"
	"testing"
)

func TestNormalize(t *testing.T) {
	c, err := ccadb.Retrieve()
	if err != nil {
		t.Fatal(err)
	}
	o, err := oneCRL.Retrieve()
	if err != nil {
		t.Fatal(err)
	}
	n := Join(c, o)
	t.Log(len(c))
	t.Log(len(o))
	t.Log(len(n))
}
