/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package kinto

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"path"
)

const kintoURL = `https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/certificates/records`

var kinto *url.URL
var repoHome = ""
var certHome = ""
var kintoFile = ""
var currentKinto *KintoSet

func init() {
	currentKinto = NewKintoSet()
	var err error
	kinto, err = url.Parse(kintoURL)
	if err != nil {
		panic(err)
	}
}

func Init(repo string) error {
	repoHome = repo
	certHome = path.Join(repoHome, "certs")
	kintoFile = path.Join(repoHome, "kinto.json")
	kinto, err := ioutil.ReadFile(path.Join(repoHome, "kinto.json"))
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	return json.Unmarshal(kinto, &currentKinto)
}

func Changes() (*ChangeSet, error) {
	resp, err := http.DefaultClient.Do(newRequest())
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	updated := NewKintoSet()
	err = json.Unmarshal(b, updated)
	if err != nil {
		return nil, err
	}
	differences := currentKinto.Diff(updated)
	if differences.Length() > 0 {
		dst := bytes.NewBuffer([]byte{})
		err = json.Indent(dst, b, "", "  ")
		if err != nil {
			return nil, err
		}
		err = ioutil.WriteFile(kintoFile, dst.Bytes(), 0666)
		if err != nil {
			return nil, err
		}
	}
	currentKinto = updated
	return differences, nil
}
