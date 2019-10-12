/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package service

import (
	"crypto/x509"
	"fmt"
	"github.com/mozilla/CCADB-Tools/capi/lib/certificateUtils"
	"github.com/mozilla/CCADB-Tools/capi/lib/expiration"
	"github.com/mozilla/CCADB-Tools/capi/lib/lint/x509lint"
	"github.com/mozilla/CCADB-Tools/capi/lib/model"
	"github.com/mozilla/CCADB-Tools/capi/lib/revocation/crl"
	"github.com/mozilla/CCADB-Tools/capi/lib/revocation/ocsp"
	log "github.com/sirupsen/logrus"
	"time"
)

func VerifyChain(chain []*x509.Certificate) model.ChainResult {
	result := model.ChainResult{}
	if len(chain) == 0 {
		return result
	}
	expirations, err := expiration.VerifyChain(chain)
	if err != nil {
		// @TODO richer conveyance back over HTTP to the client
		log.WithError(err)
		log.WithTime(time.Now())
		for i, cert := range chain {
			log.WithField(fmt.Sprintf("certificate %d", i), certificateUtils.FingerprintOf(cert))
		}
		log.Error("A query to NSS for expiration status failed")
	}
	ocsps := ocsp.VerifyChain(chain)
	crls := crl.VerifyChain(chain)
	x509lints := x509lint.LintChain(chain)
	result.Leaf = model.NewCeritifcateResult(chain[0], ocsps[0], crls[0], expirations[0], x509lints[0])

	ca := len(chain) - 1
	result.Root = model.NewCeritifcateResult(chain[ca], ocsps[ca], crls[ca], expirations[ca], x509lints[ca])

	// Just a leaf and its root, no intermediates.
	if len(chain) <= 2 {
		return result
	}

	result.Intermediates = make([]model.CertificateResult, len(chain[1:len(chain)-1]))
	for i := 1; i < len(chain)-1; i++ {
		result.Intermediates[i-1] = model.NewCeritifcateResult(chain[i], ocsps[i], crls[i], expirations[i], x509lints[i])
	}

	return result
}

func VerifySubject(subject string, root *x509.Certificate) model.ChainResult {
	chain, err := certificateUtils.GatherCertificateChain(subject)
	if err != nil {
		log.WithField("URL", subject)
		log.WithError(err)
		log.Error("failed to retrieve a certificate chain from the remote host")
		return model.ChainResult{}
	}
	chain = certificateUtils.EmplaceRoot(chain, root)
	return VerifyChain(chain)
}
