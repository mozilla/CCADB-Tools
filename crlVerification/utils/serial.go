/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package utils

import (
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"reflect"
)

type HexDecodeFailed struct {
	given string
	err   error
}

type SerialNotFound struct {
	wanted *big.Int
}

func (s SerialNotFound) Error() string {
	return fmt.Sprintf(`"%s" was not found in the given CRL`, hex.EncodeToString(s.wanted.Bytes()))
}

func (h HexDecodeFailed) Error() string {
	// @TODO test this fmting
	return fmt.Sprintf(`The serial number "%s" failed to parse from hex. error: %v`, h.given, h.err)
}

func BigIntFromHexString(serial string) (*big.Int, error) {
	s, err := hex.DecodeString(serial)
	if err != nil {
		return nil, HexDecodeFailed{serial, err}
	}
	return new(big.Int).SetBytes(s), nil
}

func FindSerial(crl *pkix.CertificateList, serial *big.Int) (pkix.RevokedCertificate, error) {
	for _, cert := range crl.TBSCertList.RevokedCertificates {
		if reflect.DeepEqual(cert.SerialNumber, serial) {
			return cert, nil
		}
	}
	return pkix.RevokedCertificate{}, SerialNotFound{serial}
}
