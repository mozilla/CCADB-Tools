package validator

import (
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
	if err != nil || strings.HasPrefix(value, " ") || strings.HasSuffix(value, " ") {
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

// ValidPEMPaste validates the pasted PEM content
func ValidPEMPaste(value string) bool {
	value = strings.TrimSpace(value)
	return strings.HasPrefix(value, "-----BEGIN CERTIFICATE-----") &&
		strings.HasSuffix(value, "-----END CERTIFICATE-----")
}
