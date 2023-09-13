/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package crtSh

import (
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"fmt"
	_ "github.com/lib/pq"
	"github.com/mozilla/CCADB-Tools/oneCRLViewer/kinto"
	"log"
	"reflect"
	"strings"
)

// https://github.com/lib/pq/issues/389
// binary_parameters=yes is because of "pq: unnamed prepared statement does not exist"
const connectionString = `postgres://guest@crt.sh/certwatch?sslmode=verify-full&binary_parameters=yes`

func GetCerts(serials []string) (map[string][]*x509.Certificate, error) {
	certs := make(map[string][]*x509.Certificate, 0)
	if len(serials) == 0 {
		return certs, nil
	}
	query, args := BuildQuery(serials)
	db, err := sql.Open("postgres", connectionString)
	if err != nil {
		return certs, err
	}
	rows, err := db.Query(query, args...)
	if err != nil {
		return certs, err
	}

	//errno := 0

	for rows.Next() {
		var b []byte
		err = rows.Scan(&b)
		if err != nil {
			log.Println(err)
			continue
		}
		cert, err := x509.ParseCertificate(b)
		if err != nil {
			hasher := sha256.New()
			hasher.Write(b)
			log.Printf("Err: %s, fingerprint: %X", err, hasher.Sum(nil))
			//f, e := os.Create(strconv.Itoa(errno))
			//if e != nil {
			//	panic(e)
			//}
			//f.Write(b)
			////pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: []byte(base64.StdEncoding.EncodeToString(b))})
			//errno += 1
			continue
		}
		serial := kinto.StripPadding(fmt.Sprintf("%X", cert.SerialNumber.Bytes()))
		if c, ok := certs[serial]; ok {
			certs[serial] = append(c, cert)
		} else {
			certs[serial] = []*x509.Certificate{cert}
		}
	}

	ccadbCerts, err := Retrieve()
	if err != nil {
		log.Println(err)
	} else {
		for serial, cert := range ccadbCerts {
			if c, ok := certs[serial]; ok {
				for _, i := range certs[serial] {
					if reflect.DeepEqual(i, cert) {
						continue
					}
				}
				certs[serial] = append(c, cert)
				log.Println("NEW!")
			} else {
				log.Println("NEW!")
				certs[serial] = []*x509.Certificate{cert}
			}
		}
	}
	return certs, nil
}

func BuildQuery(serials []string) (string, []interface{}) {
	set := strings.Builder{}
	set.WriteString(`select certificate from certificate c where x509_serialNumber(c.certificate) in (`)
	// You can't just convert a []string to a []interface{}, so while we're looping
	// over these we may as well allocate a new buffer to return for use as the argument
	// variadic in a query.
	args := make([]interface{}, 0)
	i := 0
	for index, serial := range serials {
		args = append(args, serial)
		set.WriteString(fmt.Sprintf("decode($%d, 'hex')", i+1))
		if !strings.HasPrefix(serial, "00") {
			i += 1
			padded := fmt.Sprintf("00%s", serial)
			args = append(args, padded)
			set.WriteByte(',')
			set.WriteString(fmt.Sprintf("decode($%d, 'hex')", i+1))
		}
		i += 1
		if index != len(serials)-1 {
			set.WriteByte(',')
		}
	}
	set.WriteByte(')')
	return set.String(), args
}

//func BuildQuery(serials []string) (string, []interface{}) {
//	set := strings.Builder{}
//	set.WriteString(`select certificate from certificate c where x509_serialNumber(c.certificate) in (`)
//	// You can just convert a []string to a []interface{}, so while we're looping
//	// over these we may as well allocate a new buffer to return for use as the argument
//	// variadic in a query.
//	args := make([]interface{}, len(serials))
//	for i := 0; i < len(serials); i++ {
//		args[i] = serials[i]
//		set.WriteString(fmt.Sprintf("decode($%d, 'hex')", i+1))
//		if i != len(serials)-1 {
//			set.WriteByte(',')
//		}
//	}
//	set.WriteByte(')')
//	return set.String(), args
//}

//SELECT c.ISSUER_CA_ID,
//        NULL::text ISSUER_NAME,
//        encode(x509_serialNumber(c.CERTIFICATE), 'hex') NAME_VALUE,
//        min(c.ID) MIN_CERT_ID,
//        min(ctle.ENTRY_TIMESTAMP) MIN_ENTRY_TIMESTAMP,
//        x509_notBefore(c.CERTIFICATE) NOT_BEFORE,
//        x509_notAfter(c.CERTIFICATE) NOT_AFTER
//    FROM ct_log_entry ctle,
//        certificate c
//    WHERE c.ID = ctle.CERTIFICATE_ID
//        AND x509_serialNumber(c.CERTIFICATE) = decode('016d05b10de8d1d0e3f660560a6a9b', 'hex')
//    GROUP BY c.ID, c.ISSUER_CA_ID, ISSUER_NAME, NAME_VALUE
//    ORDER BY MIN_ENTRY_TIMESTAMP DESC, NAME_VALUE, ISSUER_NAME;

// select certificate from certificate c where x509_serialNumber(c.certificate) = decode('6488b3ffd2c6bfb39d3bf05a9fc054500a8d7723', 'hex');

//https://groups.google.com/forum/#!topic/crtsh/sUmV0mBz8bQ
