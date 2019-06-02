/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package ccadb

import (
	"testing"
)

func TestGet(t *testing.T) {
	certs, err := Retrieve()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(certs)
}
