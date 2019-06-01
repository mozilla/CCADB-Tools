package normalized

import (
	"encoding/json"
	"github.com/mozilla/CCADB-Tools/oneCRLDiffCCADB/ccadb"
	"github.com/mozilla/CCADB-Tools/oneCRLDiffCCADB/oneCRL"
)

//					"Added to OneCRL"	"Cert Expired"	"Ready to Add"	Absent from Report
//Present in OneCRL		✅ 	❌	❌	❌
//Absent from OneCRL	❌	✅ 	✅ 	✅
//

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

func (n *Normalized) AbsentAndAbsent() bool {
	// unknowable?
	return false
}
