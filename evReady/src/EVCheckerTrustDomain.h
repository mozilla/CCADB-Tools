/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef EVCheckerTrustDomain_h
#define EVCheckerTrustDomain_h

#include "pkix/pkix.h"
#include "pkix/pkixnss.h"
#include "pkix/pkixtypes.h"

#include "cert.h"

#include "Util.h"

class EVCheckerTrustDomain : public mozilla::pkix::TrustDomain
{
public:
  explicit EVCheckerTrustDomain(CERTCertificate* root);

  SECStatus Init(const char* dottedEVPolicyOID, const char* evPolicyName);

  SECStatus GetFirstEVPolicyForCert(const CERTCertificate* cert,
                            /*out*/ mozilla::pkix::CertPolicyId& policy);

  mozilla::pkix::Result GetCertTrust(mozilla::pkix::EndEntityOrCA endEntityOrCA,
                                     const mozilla::pkix::CertPolicyId& policy,
                                     mozilla::pkix::Input candidateCertDER,
                             /*out*/ mozilla::pkix::TrustLevel& trustLevel);

  mozilla::pkix::Result FindIssuer(mozilla::pkix::Input encodedIssuerName,
                                   mozilla::pkix::TrustDomain::IssuerChecker& checker,
                                   mozilla::pkix::Time time);

  mozilla::pkix::Result CheckRevocation(mozilla::pkix::EndEntityOrCA endEntityOrCA,
                                        const mozilla::pkix::CertID& certID,
                                        mozilla::pkix::Time time,
                                        const mozilla::pkix::Input* stapledOCSPResponse,
                                        const mozilla::pkix::Input* aiaExtension);

  mozilla::pkix::Result IsChainValid(const mozilla::pkix::DERArray& certChain,
                                     mozilla::pkix::Time time);

  mozilla::pkix::Result VerifyRSAPKCS1SignedDigest(
    const mozilla::pkix::SignedDigest& signedDigest,
    mozilla::pkix::Input subjectPublicKeyInfo)
  {
    return mozilla::pkix::VerifyRSAPKCS1SignedDigestNSS(signedDigest,
                                                        subjectPublicKeyInfo,
                                                        nullptr);
  }

  mozilla::pkix::Result DigestBuf(mozilla::pkix::Input item,
                                  mozilla::pkix::DigestAlgorithm digestAlg,
                          /*out*/ uint8_t* digestBuf, size_t digestBufLen)
  {
    return mozilla::pkix::DigestBufNSS(item, digestAlg, digestBuf,
                                       digestBufLen);
  }

  mozilla::pkix::Result CheckSignatureDigestAlgorithm(
    mozilla::pkix::DigestAlgorithm digestAlg)
  {
    return mozilla::pkix::Success;
  }

  mozilla::pkix::Result CheckRSAPublicKeyModulusSizeInBits(
    mozilla::pkix::EndEntityOrCA endEntityOrCA, unsigned int modulusSizeInBits)
  {
    return mozilla::pkix::Success;
  }

  mozilla::pkix::Result CheckECDSACurveIsAcceptable(
    mozilla::pkix::EndEntityOrCA endEntityOrCA,
    mozilla::pkix::NamedCurve curve)
  {
    return mozilla::pkix::Success;
  }

  mozilla::pkix::Result VerifyECDSASignedDigest(
    const mozilla::pkix::SignedDigest& signedDigest,
    mozilla::pkix::Input subjectPublicKeyInfo)
  {
    return mozilla::pkix::VerifyECDSASignedDigestNSS(signedDigest,
                                                     subjectPublicKeyInfo,
                                                     nullptr);
  }

private:
  ScopedCERTCertificate mRoot;
  SECOidTag mEVPolicyOIDTag;
};

#endif // EVCheckerTrustDomain_h
