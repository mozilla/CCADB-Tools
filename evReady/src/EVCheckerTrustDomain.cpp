/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <curl/curl.h>
#include <iostream>

#include "EVCheckerTrustDomain.h"

#include "Util.h"
#include "prerror.h"
#include "secerr.h"
#include "ocsp.h"

using namespace mozilla::pkix;

EVCheckerTrustDomain::EVCheckerTrustDomain(CERTCertificate* root)
 : mRoot(root)
{
}

typedef mozilla::pkix::ScopedPtr<CERTCertificatePolicies,
                                 CERT_DestroyCertificatePoliciesExtension>
                                 ScopedCERTCertificatePolicies;
// Largely informed by
// <mozilla-central>/security/certverifier/ExtendedValidation.cpp
SECStatus
EVCheckerTrustDomain::GetFirstEVPolicyForCert(const CERTCertificate* cert,
  /*out*/ mozilla::pkix::CertPolicyId& policy)
{
  if (!cert->extensions) {
    PR_SetError(SEC_ERROR_EXTENSION_NOT_FOUND, 0);
    return SECFailure;
  }

  for (size_t i = 0; cert->extensions[i]; i++) {
    const SECItem* oid = &cert->extensions[i]->id;
    SECOidTag oidTag = SECOID_FindOIDTag(oid);
    if (oidTag != SEC_OID_X509_CERTIFICATE_POLICIES) {
      continue;
    }
    const SECItem* value = &cert->extensions[i]->value;
    ScopedCERTCertificatePolicies policies(
      CERT_DecodeCertificatePoliciesExtension(value));
    if (!policies) {
      continue;
    }
    for (CERTPolicyInfo** policyInfos = policies->policyInfos;
         *policyInfos; policyInfos++) {
      const CERTPolicyInfo* policyInfo = *policyInfos;
      SECOidTag oidTag = policyInfo->oid;
      if (oidTag == mEVPolicyOIDTag) {
        const SECOidData* oidData = SECOID_FindOIDByTag(oidTag);
        if (oidData && oidData->oid.data && oidData->oid.len > 0 &&
            oidData->oid.len <= mozilla::pkix::CertPolicyId::MAX_BYTES) {
          policy.numBytes = static_cast<uint16_t>(oidData->oid.len);
          memcpy(policy.bytes, oidData->oid.data, policy.numBytes);
          return SECSuccess;
        }
      }
    }

  }

  PR_SetError(SEC_ERROR_EXTENSION_NOT_FOUND, 0);
  return SECFailure;
}


SECStatus
EVCheckerTrustDomain::Init(const char* dottedEVPolicyOID,
                           const char* evPolicyName)
{
  SECItem evOIDItem = { siBuffer, 0, 0 };
  if (SEC_StringToOID(nullptr, &evOIDItem, dottedEVPolicyOID, 0)
        != SECSuccess) {
    PrintPRError("SEC_StringToOID failed");
    return SECFailure;
  }
  SECOidData oidData;
  oidData.oid.len = evOIDItem.len;
  oidData.oid.data = evOIDItem.data;
  oidData.offset = SEC_OID_UNKNOWN;
  oidData.desc = evPolicyName ? evPolicyName : "Test EV Policy OID";
  oidData.mechanism = CKM_INVALID_MECHANISM;
  oidData.supportedExtension = INVALID_CERT_EXTENSION;
  mEVPolicyOIDTag = SECOID_AddEntry(&oidData);
  PORT_Free(evOIDItem.data);

  if (mEVPolicyOIDTag == SEC_OID_UNKNOWN) {
    PR_SetError(SEC_ERROR_INVALID_ARGS, 0);
    return SECFailure;
  }
  return SECSuccess;
}

Result
EVCheckerTrustDomain::GetCertTrust(EndEntityOrCA endEntityOrCA,
                                   const CertPolicyId& policy,
                                   Input candidateCertDER,
                           /*out*/ TrustLevel& trustLevel)
{
  SECItem candidateCertDERSECItem = UnsafeMapInputToSECItem(candidateCertDER);
  if (SECITEM_ItemsAreEqual(&candidateCertDERSECItem, &mRoot->derCert)) {
    trustLevel = TrustLevel::TrustAnchor;
  } else {
    trustLevel = TrustLevel::InheritsTrust;
  }
  return Success;
}

Result
EVCheckerTrustDomain::FindIssuer(Input encodedIssuerName,
                                 TrustDomain::IssuerChecker& checker, Time time)
{
  SECItem encodedIssuerNameSECItem = UnsafeMapInputToSECItem(encodedIssuerName);
  ScopedCERTCertList candidates(
    CERT_CreateSubjectCertList(nullptr, CERT_GetDefaultCertDB(),
                               &encodedIssuerNameSECItem, 0, false));
  if (candidates) {
    for (CERTCertListNode* n = CERT_LIST_HEAD(candidates);
         !CERT_LIST_END(n, candidates); n = CERT_LIST_NEXT(n)) {
      Input certDER;
      Result rv = certDER.Init(n->cert->derCert.data, n->cert->derCert.len);
      if (rv != Success) {
        continue; // probably too big
      }

      bool keepGoing;
      rv = checker.Check(certDER, nullptr, keepGoing);
      if (rv != Success) {
        return rv;
      }
      if (!keepGoing) {
        break;
      }
    }
  }

  return Success;
}

struct WriteOCSPRequestDataClosure
{
  PLArenaPool* arena;
  SECItem* currentData;
};

size_t
WriteOCSPRequestData(void* ptr, size_t size, size_t nmemb, void* userdata)
{
  WriteOCSPRequestDataClosure* closure(
    reinterpret_cast<WriteOCSPRequestDataClosure*>(userdata));
  if (!closure || !closure->arena) {
    return 0;
  }

  if (!closure->currentData) {
    closure->currentData = SECITEM_AllocItem(closure->arena, nullptr,
                                             size * nmemb);
    if (!closure->currentData) {
      return 0;
    }

    memcpy(closure->currentData->data, ptr, size * nmemb);
    return size * nmemb;
  }

  SECItem* tmp = SECITEM_AllocItem(closure->arena, nullptr,
                                   closure->currentData->len + (size * nmemb));
  if (!tmp) {
    return 0;
  }
  memcpy(tmp->data, closure->currentData->data, closure->currentData->len);
  memcpy(tmp->data + closure->currentData->len, ptr, size * nmemb);
  closure->currentData = tmp;
  return size * nmemb;
}

class CURLWrapper
{
public:
  explicit CURLWrapper(CURL* curl) : mCURL(curl) {}
  ~CURLWrapper() { if (mCURL) { curl_easy_cleanup(mCURL); } }
  CURL* get() { return mCURL; }
  CURL* mCURL;
};

// Data returned is owned by arena.
Result
MakeOCSPRequest(PLArenaPool* arena, const char* url, const uint8_t* ocspRequest,
                size_t ocspRequestLength, SECItem** ocspResponsePtr)
{
  if (!arena || !ocspRequest) {
    return Result::FATAL_ERROR_INVALID_ARGS;
  }
  CURLWrapper curl(curl_easy_init());
  if (!curl.get()) {
    return Result::FATAL_ERROR_LIBRARY_FAILURE;
  }
  CURLcode res = curl_easy_setopt(curl.get(), CURLOPT_URL, url);
  if (res != CURLE_OK) {
    return Result::FATAL_ERROR_LIBRARY_FAILURE;
  }
  res = curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, ocspRequest);
  if (res != CURLE_OK) {
    return Result::FATAL_ERROR_LIBRARY_FAILURE;
  }
  res = curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDSIZE, ocspRequestLength);
  if (res != CURLE_OK) {
    return Result::FATAL_ERROR_LIBRARY_FAILURE;
  }
  mozilla::pkix::ScopedPtr<struct curl_slist, curl_slist_free_all>
    contentType(curl_slist_append(nullptr,
                                  "Content-Type: application/ocsp-request"));
  res = curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, contentType.get());
  if (res != CURLE_OK) {
    return Result::FATAL_ERROR_LIBRARY_FAILURE;
  }
  res = curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, WriteOCSPRequestData);
  if (res != CURLE_OK) {
    return Result::FATAL_ERROR_LIBRARY_FAILURE;
  }
  WriteOCSPRequestDataClosure closure({ arena, nullptr });
  res = curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &closure);
  if (res != CURLE_OK) {
    return Result::FATAL_ERROR_LIBRARY_FAILURE;
  }
  res = curl_easy_perform(curl.get());
  if (res != CURLE_OK) {
    std::cerr << "Error making OCSP request to '" << url << "': ";
    std::cerr << curl_easy_strerror(res) << std::endl;
    return Result::ERROR_OCSP_SERVER_ERROR;
  }
  if (closure.currentData) {
    *ocspResponsePtr = closure.currentData;
    return Success;
  }
  return Result::ERROR_OCSP_SERVER_ERROR;
}

// Copied and modified from CERT_GetOCSPAuthorityInfoAccessLocation and
// CERT_GetGeneralNameByType (and then copied from
// GetOCSPAuthorityInfoAccessLocation in
// security/certverifier/NSSCertDBTrustDomain.cpp. Returns SECFailure on error,
// SECSuccess with url == nullptr when an OCSP URI was not found, and
// SECSuccess with url != nullptr when an OCSP URI was found. The output url
// will be owned by the arena.
static Result
GetOCSPAuthorityInfoAccessLocation(PLArenaPool* arena,
                                   Input aiaExtension,
                                   /*out*/ char const*& url)
{
  url = nullptr;
  SECItem aiaExtensionSECItem = UnsafeMapInputToSECItem(aiaExtension);
  CERTAuthInfoAccess** aia =
    CERT_DecodeAuthInfoAccessExtension(arena, &aiaExtensionSECItem);
  if (!aia) {
    return Result::ERROR_CERT_BAD_ACCESS_LOCATION;
  }
  for (size_t i = 0; aia[i]; ++i) {
    if (SECOID_FindOIDTag(&aia[i]->method) == SEC_OID_PKIX_OCSP) {
      // NSS chooses the **last** OCSP URL; we choose the **first**
      CERTGeneralName* current = aia[i]->location;
      if (!current) {
        continue;
      }
      do {
        if (current->type == certURI) {
          const SECItem& location = current->name.other;
          // (location.len + 1) must be small enough to fit into a uint32_t,
          // but we limit it to a smaller bound to reduce OOM risk.
          if (location.len > 1024 || memchr(location.data, 0, location.len)) {
            // Reject embedded nulls. (NSS doesn't do this)
            return Result::ERROR_CERT_BAD_ACCESS_LOCATION;
          }
          // Copy the non-null-terminated SECItem into a null-terminated string.
          char* nullTerminatedURL(static_cast<char*>(
                                    PORT_ArenaAlloc(arena, location.len + 1)));
          if (!nullTerminatedURL) {
            return Result::FATAL_ERROR_NO_MEMORY;
          }
          memcpy(nullTerminatedURL, location.data, location.len);
          nullTerminatedURL[location.len] = 0;
          url = nullTerminatedURL;
          return Success;
        }
        current = CERT_GetNextGeneralName(current);
      } while (current != aia[i]->location);
    }
  }

  return Success;
}

Result
EVCheckerTrustDomain::CheckRevocation(EndEntityOrCA endEntityOrCA,
                                      const CertID& certID, Time time,
                                      const Input* stapledOCSPResponse,
                                      const Input* aiaExtension)
{
  if (!aiaExtension) {
      // BRs and EV Guidelines no longer require OCSP,
      // but OCSP will be checked if it is provided.
    return Success;
  }
  ScopedPLArenaPool arena(PORT_NewArena(DER_DEFAULT_CHUNKSIZE));
  if (!arena) {
    return Result::FATAL_ERROR_NO_MEMORY;
  }
  const char* url = nullptr; // owned by the arena
  Result rv = GetOCSPAuthorityInfoAccessLocation(arena.get(), *aiaExtension, url);
  if (rv != Success) {
    return rv;
  }

  uint8_t ocspRequest[OCSP_REQUEST_MAX_LENGTH];
  size_t ocspRequestLength;
  rv = CreateEncodedOCSPRequest(*this, certID, ocspRequest, ocspRequestLength);
  if (rv != Success) {
    return rv;
  }

  SECItem* ocspResponse = nullptr;
  rv = MakeOCSPRequest(arena.get(), url, ocspRequest, ocspRequestLength,
                       &ocspResponse);
  if (rv != Success) {
    return rv;
  }
  Input ocspResponseInput;
  rv = ocspResponseInput.Init(ocspResponse->data, ocspResponse->len);
  if (rv != Success) {
    return rv;
  }

  // Bug 991815: The BR allow OCSP for intermediates to be up to one year old.
  // Since this affects EV there is no reason why DV should be more strict
  // so all intermediatates are allowed to have OCSP responses up to one year
  // old.
  uint16_t maxOCSPLifetimeInDays = 10;
  if (endEntityOrCA == EndEntityOrCA::MustBeCA) {
    maxOCSPLifetimeInDays = 365;
  }

  bool expired;
  return VerifyEncodedOCSPResponse(*this, certID, time, maxOCSPLifetimeInDays,
                                   ocspResponseInput, expired);
}

Result
EVCheckerTrustDomain::IsChainValid(const DERArray& certChain, Time)
{
  if (certChain.GetLength() < 3) {
    return Result::ERROR_POLICY_VALIDATION_FAILED;
  }

  return Success;
}
