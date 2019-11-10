package main

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"fmt"
	"os"
)

func main() {
	i := os.Args[1]
	d, err := base64.StdEncoding.DecodeString(i)
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}
	var name pkix.RDNSequence
	_, err = asn1.Unmarshal(d, &name)
	if err != nil {
		fmt.Print(err)
		os.Exit(1)
	}
	fmt.Print(name)
}