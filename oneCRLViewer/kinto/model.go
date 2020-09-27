/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package kinto

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// Raw OneCRL representations
type KintoArray struct {
	Data []KintoEntry `json:"data"`
}

type KintoEntry struct {
	Schema       int64   `json:"schema"`
	Details      Details `json:"details"`
	Enabled      bool    `json:"enabled"`
	IssuerName   string  `json:"issuerName"`
	SerialNumber string  `json:"serialNumber"`
	ID           string  `json:"id"`
	LastModified int64   `json:"lastModified"`
}

type Details struct {
	Bug     string `json:"bug"`
	Who     string `json:"who"`
	Why     string `json:"why"`
	Name    string `json:"name"`
	Created string `json:"created"`
}

func (k *KintoEntry) Key() string {
	return fmt.Sprintf("%s%s", k.ReadableIssuer(), k.HexSerial())
}

func (k *KintoEntry) SameIssuer(cert *x509.Certificate) bool {
	var name pkix.RDNSequence
	i, _ := base64.StdEncoding.DecodeString(k.IssuerName)
	asn1.Unmarshal(i, &name)
	return comp(name, cert.Issuer.ToRDNSequence())
}

func ToKintoKey(cert *x509.Certificate) string {
	return fmt.Sprintf("%s%X", cert.Issuer.ToRDNSequence().String(), cert.SerialNumber.Bytes())
}

func (k *KintoEntry) ReadableIssuer() string {
	i, err := base64.StdEncoding.DecodeString(k.IssuerName)
	if err != nil {
		panic(err)
	}
	if string(i) == "" {
		return ""
	}
	var name pkix.RDNSequence
	_, err = asn1.Unmarshal(i, &name)
	if err != nil {
		panic(err)
	}
	return name.String()
}

func (k *KintoEntry) HexSerial() string {
	i, err := base64.StdEncoding.DecodeString(k.SerialNumber)
	if err != nil {
		panic(err)
	}
	return StripPadding(fmt.Sprintf("%X", i))
}

func (k *KintoEntry) Timestamp() string {
	return time.Unix(0, k.LastModified).String()
}

// Our representations

type KintoSet struct {
	inner map[KintoEntry]bool
}

func NewKintoSet() *KintoSet {
	return &KintoSet{inner: make(map[KintoEntry]bool, 0)}
}

func (k *KintoSet) UnmarshalJSON(data []byte) error {
	var kinto KintoArray
	err := json.Unmarshal(data, &kinto)
	if err != nil {
		return err
	}
	if k.inner == nil {
		k.inner = make(map[KintoEntry]bool)
	}
	for _, entry := range kinto.Data {
		k.inner[entry] = true
	}
	return nil
}

func (k *KintoSet) Diff(other *KintoSet) *ChangeSet {
	changeSet := NewChangeSet()
	for entry := range other.inner {
		if ok := k.inner[entry]; !ok {
			changeSet.Added(entry)
		}
	}
	for entry := range k.inner {
		if ok := other.inner[entry]; !ok {
			changeSet.Removed(entry)
		}
	}
	return changeSet
}

type Change = bool

const Added Change = true
const Removed Change = false

type ChangeSet struct {
	bucket map[string][]KintoEntry
	inner  map[KintoEntry]Change
	index  map[string]KintoEntry
	cindex map[KintoEntry]*x509.Certificate
}

func NewChangeSet() *ChangeSet {
	return &ChangeSet{bucket: make(map[string][]KintoEntry), inner: make(map[KintoEntry]Change, 0), index: make(map[string]KintoEntry), cindex: make(map[KintoEntry]*x509.Certificate, 0)}
}

func (c *ChangeSet) add(entry KintoEntry) {
	serial := entry.HexSerial()
	if b, ok := c.bucket[serial]; ok {
		c.bucket[serial] = append(b, entry)
	} else {
		c.bucket[serial] = []KintoEntry{entry}
	}
	c.index[entry.Key()] = entry
	c.cindex[entry] = nil
}

func (c *ChangeSet) Added(entry KintoEntry) {
	c.inner[entry] = Added
	c.add(entry)
}

func (c *ChangeSet) Removed(entry KintoEntry) {
	c.inner[entry] = Removed
	c.add(entry)
}

func (c *ChangeSet) Changed() bool {
	return len(c.inner) > 0
}

func (c *ChangeSet) Length() int {
	return len(c.inner)
}

func (c *ChangeSet) Keys() []string {
	keys := make([]string, c.Length())
	index := 0
	for entry := range c.inner {
		keys[index] = entry.Key()
		index += 1
	}
	return keys
}

func (c *ChangeSet) Serials() []string {
	keys := make([]string, c.Length())
	index := 0
	for entry := range c.inner {
		keys[index] = entry.HexSerial()
		index += 1
	}
	return keys
}

func (c *ChangeSet) Entries() []KintoEntry {
	entries := make([]KintoEntry, c.Length())
	i := 0
	for entry := range c.inner {
		entries[i] = entry
		i += 1
	}
	return entries
}

func (c *ChangeSet) Get(cert *x509.Certificate) (KintoEntry, bool) {
	if entry, ok := c.index[ToKintoKey(cert)]; ok {
		return entry, true
	}
	return KintoEntry{}, false
}

func (c *ChangeSet) Associate(certs map[string][]*x509.Certificate) {
	for serial, candidates := range certs {
		for _, entry := range c.bucket[serial] {
			for _, candidate := range candidates {
				if entry.SameIssuer(candidate) {
					c.cindex[entry] = candidate
					break
				}
			}
		}
	}
}

type CanonicalEntry struct {
	Entry       KintoEntry
	Certificate *x509.Certificate
	State       Change
}

func (c *ChangeSet) State() []CanonicalEntry {
	entries := make([]CanonicalEntry, 0)
	for entry, change := range c.inner {
		entries = append(entries, CanonicalEntry{
			Entry:       entry,
			Certificate: c.cindex[entry],
			State:       change,
		})
	}
	return entries
}
