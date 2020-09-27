/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package kinto

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestLength(t *testing.T) {
	resp, err := http.DefaultClient.Do(newRequest())
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var k KintoArray
	err = json.NewDecoder(resp.Body).Decode(&k)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(len(k.Data))
}
