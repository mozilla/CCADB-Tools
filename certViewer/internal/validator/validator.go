/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package validator

import (
	"mime/multipart"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"
)

type Validator struct {
	FieldErrors map[string]string
}

func (v *Validator) Valid() bool {
	return len(v.FieldErrors) == 0
}

func (v *Validator) AddFieldError(key, message string) {
	if v.FieldErrors == nil {
		v.FieldErrors = make(map[string]string)
	}

	if _, exists := v.FieldErrors[key]; !exists {
		v.FieldErrors[key] = message
	}
}

func (v *Validator) CheckField(ok bool, key, message string) {
	if !ok {
		v.AddFieldError(key, message)
	}
}

// NotBlank checks to make sure the field isn't blank
func NotBlank(value string) bool {
	return strings.TrimSpace(value) != ""
}

// MaxChars checks to make sure the field isn't over the specified number of characters
func MaxChars(value string, n int) bool {
	return utf8.RuneCountInString(value) <= n
}

// ValidURL validates the provided hostname
func ValidURL(value string) bool {
	_, err := url.Parse(value)
	if err != nil {
		return false
	} else {
		return true
	}
}

// ValidOID validates the provided OID
func ValidOID(value string) bool {
	re := regexp.MustCompile(`^([0-2])((\.0)|(\.[1-9][0-9]*))*$`)

	return re.MatchString(strings.TrimSpace(value))
}

// NoPEMs validates that there is at least a pasted PEM or an uploaded PEM file
func NoPEMs(pemPaste string, pemUpload *multipart.FileHeader) bool {
	if pemPaste == "" && pemUpload == nil {
		return false
	} else {
		return true
	}
}

// BothPEMs validates that only one or the other types of PEM are submitted
func BothPEMs(pemPaste string, pemUpload *multipart.FileHeader) bool {
	if pemPaste != "" && pemUpload != nil {
		return false
	} else {
		return true
	}
}

// ValidPEM validates PEM content - pasted or uploaded
func ValidPEM(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "-----BEGIN CERTIFICATE-----") &&
		strings.HasSuffix(value, "-----END CERTIFICATE-----")
}
