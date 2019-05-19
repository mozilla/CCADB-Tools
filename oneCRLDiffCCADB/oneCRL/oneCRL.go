package oneCRL

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
)

const OneCRLEndpoint = "https://firefox.settings.services.mozilla.com/v1/buckets/blocklists/collections/certificates/records"

type OneCRLIntermediates struct {
	Data []OneCRLIntermediate `json:"data"`
}

type OneCRLIntermediate struct {
	Schema  int `json:"schema"`
	Details struct {
		Bug     string `json:"bug"`
		Who     string `json:"who"`
		Why     string `json:"why"`
		Name    string `json:"name"`
		Created string `json:"created"`
	} `json:"details"`
	Enabled      bool   `json:"enabled"`
	IssuerName   string `json:"issuerName"`
	SerialNumber string `json:"serialNumber"`
	Id           string `json:"id"`
	LastModified int    `json:"last_modified"`
}

func Retrieve() (OneCRLIntermediates, error) {
	var intermediates OneCRLIntermediates
	resp, err := http.DefaultClient.Get(OneCRLEndpoint)
	if err != nil {
		return intermediates, err
	}
	defer resp.Body.Close()
	err = json.NewDecoder(resp.Body).Decode(&intermediates)
	return intermediates, err
}

func tostring() string {
	resp, err := http.DefaultClient.Get(OneCRLEndpoint)
	if err != nil {
		panic(err)
	}
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	return string(b)
}
