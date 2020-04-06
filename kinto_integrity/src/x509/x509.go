package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

type Response struct {
	RDN   string `json:"rdn"`
	Error string `json:"error"`
}

func ToRDN(w http.ResponseWriter, r *http.Request) {
	var err error
	var RDN string
	encoder := json.NewEncoder(w)
	defer func() {
		var errString = ""
		if err != nil {
			w.WriteHeader(400)
			errString = err.Error()
		} else {
			w.WriteHeader(200)
		}
		encoder.Encode(&Response{
			RDN:   RDN,
			Error: errString,
		})
	}()
	var b64 []byte
	b64, err = ioutil.ReadAll(r.Body)
	if err != nil {
		return
	}
	var raw []byte
	raw, err = base64.StdEncoding.DecodeString(string(b64))
	if err != nil {
		return
	}
	var name pkix.RDNSequence
	_, err = asn1.Unmarshal(raw, &name)
	if err != nil {
		return
	}
	RDN = fmt.Sprint(name)
}

func main() {
	port := os.Getenv("GO_PORT")
	if port == "" {
		port = "8081"
	}
	log.Printf("golang x509 subtool listening on %v\n", port)
	http.HandleFunc("/", ToRDN)
	if err := http.ListenAndServe(":"+port, nil); err != nil {
		log.Fatal(err)
	}
}