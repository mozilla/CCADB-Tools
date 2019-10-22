package model

import (
	"crypto/x509"
	"github.com/mozilla/CCADB-Tools/capi/lib/certificateUtils"
	"github.com/mozilla/CCADB-Tools/capi/lib/lint/certlint"
	"github.com/mozilla/CCADB-Tools/capi/lib/lint/x509lint"
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
	for _, err := range c.X509Lint.Errors {
		opinion.Result = FAIL
		opinion.Errors = append(opinion.Errors, Concern{
			Raw:            err,
			Interpretation: "",
			Advise:         "",
		})
	}
	if err := c.X509Lint.CmdError; err != nil {
		opinion.Result = FAIL
		opinion.Errors = append(opinion.Errors, Concern{
			Raw:            *err,
			Interpretation: "",
			Advise:         "",
		})
	}
	for _, err := range c.Certlint.Certlint.Errors {
		opinion.Result = FAIL
		opinion.Errors = append(opinion.Errors, Concern{
			Raw:            err,
			Interpretation: "",
			Advise:         "",
		})
	}
	if err := c.Certlint.Certlint.CmdError; err != nil {
		opinion.Result = FAIL
		opinion.Errors = append(opinion.Errors, Concern{
			Raw:            *err,
			Interpretation: "",
			Advise:         "",
		})
	}
	for _, err := range c.Certlint.Cablint.Errors {
		opinion.Result = FAIL
		opinion.Errors = append(opinion.Errors, Concern{
			Raw:            err,
			Interpretation: "",
			Advise:         "",
		})
	}
	for _, err := range c.Certlint.Cablint.Fatal {
		opinion.Result = FAIL
		opinion.Errors = append(opinion.Errors, Concern{
			Raw:            err,
			Interpretation: "",
			Advise:         "",
		})
	}
	for _, err := range c.Certlint.Cablint.Bug {
		opinion.Result = FAIL
		opinion.Errors = append(opinion.Errors, Concern{
			Raw:            err,
			Interpretation: "",
			Advise:         "",
		})
	}
	if err := c.Certlint.Cablint.CmdError; err != nil {
		opinion.Result = FAIL
		opinion.Errors = append(opinion.Errors, Concern{
			Raw:            *err,
			Interpretation: "",
			Advise:         "",
		})
	}
}

type CertificateLintResult struct {
	X509Lint x509lint.X509Lint
	Certlint certlint.Certlint
	CrtSh    string
}

func NewCertificateLintResult(original *x509.Certificate, X509 x509lint.X509Lint, clint certlint.Certlint) CertificateLintResult {
	return CertificateLintResult{
		X509Lint: X509,
		Certlint: clint,
		CrtSh:    "https://crt.sh/?q=" + certificateUtils.FingerprintOf(original),
	}
}
