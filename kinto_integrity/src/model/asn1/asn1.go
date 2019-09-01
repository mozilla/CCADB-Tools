package main

import (
	"bufio"
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
)

func main() {
	r := bufio.NewReader(os.Stdin)
	w := json.NewEncoder(os.Stdout)
	newline := []byte(fmt.Sprintln("-1"))
	for line, err := r.ReadBytes('\n'); err == nil && !reflect.DeepEqual(line, newline); line, err = r.ReadBytes('\n') {
		err := w.Encode(deser(bytes.TrimRight(line, "\n")))
		if err != nil {
			panic(err)
		}
	}
}

type Deserialized struct {
	CommonName   string `json:"common_name"`
	Organization string `json:"organization"`
	Err          error  `json:"error"`
}

func deser(issuer []byte) (d Deserialized) {
	rawBytes := make([]byte, base64.StdEncoding.DecodedLen(len(issuer)))
	_, d.Err = base64.StdEncoding.Decode(rawBytes, issuer)
	if d.Err != nil {
		return
	}
	var name pkix.RDNSequence
	_, d.Err = asn1.Unmarshal(rawBytes, &name)
	if d.Err != nil {
		return
	}
	for _, r := range name {
		for _, attr := range r {
			if attr.Type.Equal([]int{2, 5, 4, 3}) {
				d.CommonName = fmt.Sprint(attr.Value)
			} else if attr.Type.Equal([]int{2, 5, 4, 10}) {
				d.Organization = fmt.Sprint(attr.Value)
			}
		}
	}
	return
}
