/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package utils

import (
	"crypto/x509/pkix"
	"fmt"
	"time"
)

const TimeFormat = "2006/01/02"

func TimeFromString(date string) (time.Time, error) {
	return time.Parse(TimeFormat, date)
}

func ValidateRevocationDate(cert pkix.RevokedCertificate, ourRevocationDate time.Time) error {
	theirRevocationDate := cert.RevocationTime
	if theirRevocationDate.Year() != ourRevocationDate.Year() || theirRevocationDate.Month() != ourRevocationDate.Month() || theirRevocationDate.Day() != ourRevocationDate.Day() {
		return RevocationtimeError{ourRevocationDate, theirRevocationDate}
	}
	return nil
}

type RevocationtimeError struct {
	wanted time.Time
	got    time.Time
}

func (r RevocationtimeError) Error() string {
	return fmt.Sprintf("Revocation dates did not match. We wanted %s, but got %s", r.wanted.Format(TimeFormat), r.got.Format(TimeFormat))
}
