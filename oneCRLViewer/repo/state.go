/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package repo

import (
	"github.com/mozilla/CCADB-Tools/oneCRLViewer/kinto"
)

type CertRepo struct {
}

type Cert struct {
	Kinto       kinto.KintoEntry
	Certificate []byte
	Dirname     string
}
