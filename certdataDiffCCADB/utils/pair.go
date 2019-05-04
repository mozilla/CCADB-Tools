/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package utils

// Pair holds a normalized certdata.txt entry, it's sister CCADB,
// as well a slice of what fields between the two are differnt.
type Pair struct {
	Certdata *Entry
	CCADB    *Entry
	Diffs    []string
}

// MapPairs map all of the entries in certdata.txt to entries in the CCADB
// report. Entries are matched together if they:
//
// 1. Have the same serial number (normalized for leading zeroes)
// 	or
// 2. They have the exact same PEM.
//	or
// 3. They have the exact same Common Name.
//
// Any entries for which a mapping could not be made are returned
// in the 'rest' slice.
func MapPairs(cd, ccadb []*Entry) (pairs []Pair, unmatchedT []*Entry, unmatchedUT []*Entry) {
	idMap := make(map[string]*Entry) // DN || serial
	ftocd := make(map[string]*Entry) // fingerprint
	for _, e := range cd {
		idMap[e.UniqueID()] = e
		ftocd[e.Fingerprint] = e
	}
	var pair Pair
	var match *Entry
	var ok bool
	for _, e := range ccadb {
		id := e.UniqueID()
		if match, ok = idMap[id]; ok {
			pair = NewPair(match, e)
		} else if match, ok = ftocd[e.Fingerprint]; ok {
			pair = NewPair(match, e)
		} else {
			if !(e.TrustWeb || e.TrustEmail) {
				unmatchedUT = append(unmatchedUT, e)
			} else {
				unmatchedT = append(unmatchedT, e)
			}
			continue
		}
		pairs = append(pairs, pair)
		// Avoid matching duplicates
		delete(idMap, match.UniqueID())
		delete(ftocd, match.Fingerprint)
	}
	for _, e := range idMap {
		if !(e.TrustWeb || e.TrustEmail) {
			unmatchedUT = append(unmatchedUT, e)
		} else {
			unmatchedT = append(unmatchedT, e)
		}
	}
	return
}

// NewPair discovers the difference between a matched certdata.txt entry
// and a CCADB report entry and constructs a new Pair.
func NewPair(cd, ccadb *Entry) (p Pair) {
	p.Certdata = cd
	p.CCADB = ccadb
	p.Diffs = make([]string, 0)
	if cd.OrganizationName != ccadb.OrganizationName {
		p.Diffs = append(p.Diffs, "OrganizationName")
	}
	if cd.OrganizationalUnitName != ccadb.OrganizationalUnitName {
		p.Diffs = append(p.Diffs, "OrganizationalUnitName")
	}
	if cd.CommonName != ccadb.CommonName {
		p.Diffs = append(p.Diffs, "CommonName")
	}
	if cd.SerialNumber != ccadb.SerialNumber {
		p.Diffs = append(p.Diffs, "SerialNumber")
	}
	if cd.PEM != ccadb.PEM {
		p.Diffs = append(p.Diffs, "PEM")
	}
	if cd.Fingerprint != ccadb.Fingerprint {
		p.Diffs = append(p.Diffs, "Fingerprint")
	}
	if cd.TrustWeb != ccadb.TrustWeb {
		p.Diffs = append(p.Diffs, "TrustWeb")
	}
	if cd.TrustEmail != ccadb.TrustEmail {
		p.Diffs = append(p.Diffs, "TrustEmail")
	}
	return
}
