/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package repo

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/mozilla/CCADB-Tools/oneCRLViewer/git"
	"github.com/mozilla/CCADB-Tools/oneCRLViewer/kinto"
	"github.com/mozilla/CCADB-Tools/oneCRLViewer/markdown"
	"io/ioutil"
	"log"
	"os"
	"path"
	"path/filepath"
	"strings"
)

var Repo = ``
var CertificateDirectory = ``

var database = ``

func Init(repo string) {
	Repo = repo
	CertificateDirectory = filepath.Join(repo, "certs")
	database = filepath.Join(repo, "db.json")
}

func Update(changes []kinto.CanonicalEntry) error {
	db, err := getDB()
	if err != nil {
		return err
	}
	start := len(db)
	for _, change := range changes {
		nc := NewCanonicalEntry(change)
		nc.EffectChange()
		if nc.state == kinto.Added {
			db = append(db, *nc)
		}
	}
	err = saveDB(db)
	if err != nil {
		return err
	}
	err = commit(db[start:])
	if err != nil {
		return err
	}
	err = NewFrontPage(db)
	if err != nil {
		return err
	}
	g := git.NewRepo(Repo)
	err = g.Add(".")
	if err != nil {
		return err
	}
	return g.Commit("INDEX UPDATE")
}

func commit(changes []CanonicalEntry) error {
	message := &strings.Builder{}
	fmt.Fprintln(message, "CERT COMMIT")
	for _, change := range changes {
		fmt.Fprintf(message, "Added Issuer: %s ----- Serial: %s\n", change.KintoEntry.ReadableIssuer(), change.KintoEntry.HexSerial())
	}
	g := git.NewRepo(Repo)
	err := g.Add(".")
	if err != nil {
		return err
	}
	return g.Commit(message.String())
}

func getDB() ([]CanonicalEntry, error) {
	db := make([]CanonicalEntry, 0)
	f, err := os.Open(database)
	defer f.Close()
	switch true {
	case os.IsNotExist(err):
		return db, nil
	case err != nil:
		return db, err
	}
	return db, json.NewDecoder(f).Decode(&db)
}

func saveDB(db []CanonicalEntry) error {
	f, err := os.Create(database)
	if err != nil {
		return err
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(db)
}

type CanonicalEntry struct {
	KintoEntry  kinto.KintoEntry
	Certificate *x509.Certificate
	Dirname     string
	state       kinto.Change `json:"-"` // @TODO try to JSON ignore this instead of making it a pointer
}

func (c *CanonicalEntry) MarshalJSON() ([]byte, error) {
	var p []byte
	if c.Certificate != nil {
		p = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate.Raw})
	}
	obj := struct {
		KintoEntry  kinto.KintoEntry
		Certificate string
		Dirname     string
	}{
		c.KintoEntry,
		string(p),
		c.Dirname,
	}
	return json.Marshal(obj)
}

func (c *CanonicalEntry) UnmarshalJSON(b []byte) error {
	obj := new(struct {
		KintoEntry  kinto.KintoEntry
		Certificate string
		Dirname     string
	})
	err := json.Unmarshal(b, obj)
	if err != nil {
		return err
	}
	var cert *x509.Certificate
	if obj.Certificate != "" {
		p, _ := pem.Decode([]byte(obj.Certificate))
		cert, err = x509.ParseCertificate(p.Bytes)
		if err != nil {
			return err
		}
	}
	c.Certificate = cert
	c.KintoEntry = obj.KintoEntry
	c.Dirname = obj.Dirname
	c.state = kinto.Added
	return nil
}

func NewCanonicalEntry(e kinto.CanonicalEntry) *CanonicalEntry {
	entry := new(CanonicalEntry)
	entry.KintoEntry = e.Entry
	entry.Certificate = e.Certificate
	entry.state = e.State
	if entry.Certificate == nil {
		entry.Dirname = fmt.Sprintf("Serial_%s", e.Entry.HexSerial())
	} else {
		hasher := sha256.New()
		hasher.Write(entry.Certificate.Raw)
		b := hasher.Sum(nil)
		entry.Dirname = fmt.Sprintf("%X", b)
	}
	return entry
}

func (c *CanonicalEntry) Save() error {
	certDir := path.Join(CertificateDirectory, c.Dirname)
	err := os.MkdirAll(certDir, 0777)
	if err != nil {
		return err
	}
	if c.Certificate != nil {
		err = ioutil.WriteFile(path.Join(certDir, "cert.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate.Raw}), 0666)
		if err != nil {
			return err
		}
	}
	kintoJson, err := json.MarshalIndent(c.KintoEntry, "", "  ")
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(path.Join(certDir, "kinto.json"), kintoJson, 0666)
	if err != nil {
		return err
	}
	m := markdown.Markdown{}
	var title string
	if c.Certificate == nil {
		title = c.KintoEntry.ReadableIssuer()
	} else {
		title = c.Certificate.Subject.CommonName
	}
	m.H1().WriteNL(title).
		H3().WriteNL("Snapshot of crt.sh").
		H5().Write("Click ").Link("here", c.CrtSh()).WriteNL(" for a live crt.sh report").
		WriteNL().Divider()
	err = ioutil.WriteFile(path.Join(certDir, "README.md"), []byte(m.String()), 0666)
	if err != nil {
		return err
	}
	return nil
}

func (c *CanonicalEntry) Delete() error {
	return os.RemoveAll(c.Location())
}

func (c *CanonicalEntry) CrtSh() string {
	switch c.Certificate {
	case nil:
		return fmt.Sprintf("https://crt.sh/?serial=%s", c.KintoEntry.HexSerial())
	default:
		return fmt.Sprintf("https://crt.sh/?q=%s", c.Dirname)
	}

}

func (c *CanonicalEntry) Location() string {
	return fmt.Sprintf(path.Join(CertificateDirectory, c.Dirname))
}

var remoteFailedAlready = false

func (c *CanonicalEntry) FrontPageRow(commit string) []markdown.Renderer {
	repo, err := git.NewRepo(Repo).Remote()
	link := ""
	if err != nil {
		if remoteFailedAlready {
			/// Just to not be noisy. If this happens once it will happen a bunch.
		} else {
			remoteFailedAlready = true
			log.Println("Failed to get git remote information. This is not fatal, however hyperlinks will be broken in the README.md")
		}
	} else {
		link = fmt.Sprintf("%s/tree/%s/certs/%s", repo, commit, c.Dirname)
	}
	return []markdown.Renderer{
		&markdown.Text{c.KintoEntry.ReadableIssuer()},
		&markdown.Text{c.KintoEntry.HexSerial()},
		&markdown.Text{(&markdown.Link{c.KintoEntry.HexSerial(), link}).String()},
		&markdown.Text{c.KintoEntry.Timestamp()},
	}
}

func (c *CanonicalEntry) EffectChange() error {
	switch c.state {
	case kinto.Added:
		return c.Save()
	case kinto.Removed:
		return c.Delete()
	}
	return nil
}
