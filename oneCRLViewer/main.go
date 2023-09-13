/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main // import "github.com/mozilla/CCADB-Tools/oneCRLViewer"
import (
	"fmt"
	"github.com/mozilla/CCADB-Tools/oneCRLViewer/crtSh"
	"github.com/mozilla/CCADB-Tools/oneCRLViewer/kinto"
	"github.com/mozilla/CCADB-Tools/oneCRLViewer/repo"
	"log"
	"os"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: go run main.go </path/to/repo>")
		os.Exit(1)
	}
	certDir := os.Args[1]
	repo.Init(certDir)
	if err := kinto.Init(certDir); err != nil {
		panic(err)
	}
	changes, err := kinto.Changes()
	if err != nil {
		log.Println(err)
		return
	}
	if !changes.Changed() {
		log.Println("no changes")
		return
	}
	certs, err := crtSh.GetCerts(changes.Serials())
	if err != nil {
		log.Println(err)
		return
	}
	changes.Associate(certs)
	err = repo.Update(changes.State())
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
