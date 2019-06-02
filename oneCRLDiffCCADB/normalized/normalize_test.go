/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

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
