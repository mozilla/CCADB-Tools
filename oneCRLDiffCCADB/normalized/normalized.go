/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package normalized

import (
	"encoding/json"
	"github.com/mozilla/CCADB-Tools/oneCRLDiffCCADB/ccadb"
	"github.com/mozilla/CCADB-Tools/oneCRLDiffCCADB/oneCRL"
	"strings"
)

// Join performs a join on the entries from the CCADB and OneCRL using the "Key" constructed by those entities.
func Join(c map[string]*ccadb.Entry, o map[string]*oneCRL.OneCRLIntermediate) []*Normalized {
	intermediate := make(map[string]*Normalized, len(c))
	for key, cert := range c {
		n := new(Normalized)
		n.Entry = cert
		intermediate[key] = n
	}
	for key, cert := range o {
		n := intermediate[key]
		if n == nil {
			n = new(Normalized)
		}
		n.OneCRLIntermediate = cert
	}
	flat := make([]*Normalized, 0)
	for _, v := range intermediate {
		flat = append(flat, v)
	}
	return flat
}

type Normalized struct {
	*ccadb.Entry
	*oneCRL.OneCRLIntermediate
}

func (n Normalized) MarshalJSON() ([]byte, error) {
	return json.Marshal(n.Entry)
}

func New(c *ccadb.Entry, o *oneCRL.OneCRLIntermediate) *Normalized {
	return &Normalized{c, o}
}

// The consequent grouping of methods encode the following truth table.
//
//						"Added to OneCRL"	"Cert Expired"	"Ready to Add"	Absent from Report
//	Present in OneCRL		✅ 					❌				❌				❌
//	Absent from OneCRL		❌					✅ 				✅			 	✅
//
// ...where a ✅ is typically considered fine and a ❌ is considered an error case, although
// this tool does not do any deeper interpretation than merely providing the results
// of building this table.

func (n *Normalized) AddedAndPresent() bool {
	return n.Entry != nil && n.OneCRLIntermediate != nil && n.Entry.RevocationStatus == ccadb.Added
}

func (n *Normalized) ExpiredAndPresent() bool {
	return n.Entry != nil && n.OneCRLIntermediate != nil && n.Entry.RevocationStatus == ccadb.Expired
}

func (n *Normalized) ReadyAndPresent() bool {
	return n.Entry != nil && n.OneCRLIntermediate != nil && n.Entry.RevocationStatus == ccadb.ReadyToAdd
}

func (n *Normalized) AbsentAndPresent() bool {
	return n.Entry == nil && n.OneCRLIntermediate != nil
}

func (n *Normalized) AddedAndAbsent() bool {
	return n.Entry != nil && n.OneCRLIntermediate == nil && n.Entry.RevocationStatus == ccadb.Added
}

func (n *Normalized) ExpiredAndAbsent() bool {
	return n.Entry != nil && n.OneCRLIntermediate == nil && n.Entry.RevocationStatus == ccadb.Expired
}

func (n *Normalized) ReadyAndAbsent() bool {
	return n.Entry != nil && n.OneCRLIntermediate == nil && n.Entry.RevocationStatus == ccadb.ReadyToAdd
}

func (n *Normalized) NoRevocationStatus() bool {
	return n.Entry != nil && strings.Trim(n.RevocationStatus, " ") == ""
}

func (n *Normalized) AbsentAndAbsent() bool {
	// unknowable?
	return false
}
