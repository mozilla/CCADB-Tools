package model

import (
	"crypto/x509"

	"github.com/mozilla/CCADB-Tools/capi/lib/certificateUtils"
	"github.com/mozilla/CCADB-Tools/capi/lib/lint/pkimetal"
)

type ChainLintResult struct {
	Subject       string
	Leaf          CertificateLintResult
	Intermediates []CertificateLintResult
	Opinion       Opinion
	Error         string
}

func NewChainLintResult(subject string) ChainLintResult {
	return ChainLintResult{
		Subject: subject,
	}
}

func (c *ChainLintResult) Finalize(leaf CertificateLintResult, intermediates []CertificateLintResult) {
	c.Leaf = leaf
	c.Intermediates = intermediates
	c.Opinion = NewOpinion()
	c.Opinion.Result = PASS
	interpretLint(c.Leaf, &c.Opinion)
	for _, intermediate := range intermediates {
		interpretLint(intermediate, &c.Opinion)
	}
}

func interpretLint(c CertificateLintResult, opinion *Opinion) {
	for _, err := range c.PkiMetal.Fatal {
		opinion.Result = FAIL
		opinion.Errors = append(opinion.Errors, Concern{
			Raw:            err,
			Interpretation: "",
			Advise:         "",
		})
	}

	for _, err := range c.PkiMetal.Bug {
		opinion.Result = FAIL
		opinion.Errors = append(opinion.Errors, Concern{
			Raw:            err,
			Interpretation: "",
			Advise:         "",
		})
	}

	for _, err := range c.PkiMetal.Error {
		opinion.Result = FAIL
		opinion.Errors = append(opinion.Errors, Concern{
			Raw:            err,
			Interpretation: "",
			Advise:         "",
		})
	}
}

type CertificateLintResult struct {
	PkiMetal pkimetal.PKIMetal
	CrtSh    string
}

func NewCertificateLintResult(original *x509.Certificate, results pkimetal.PKIMetal) CertificateLintResult {
	return CertificateLintResult{
		PkiMetal: results,
		CrtSh:    "https://crt.sh/?sha256=" + certificateUtils.FingerprintOf(original),
	}
}
