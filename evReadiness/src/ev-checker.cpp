/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

#include "EVCheckerTrustDomain.h"
#include "Util.h"
#include "nss.h"
#include "hasht.h"
#include "pk11pub.h"
#include "plbase64.h"
#include "plgetopt.h"
#include "prerror.h"
#include "secerr.h"

void
PrintUsage(const char* argv0)
{
  std::cerr << "Usage: " << argv0 << " <-c certificate list file (PEM format)>";
  std::cerr << " <-o dotted EV policy OID> <-h hostname>";
  std::cerr << " [-d EV policy description]";
  std::cerr << std::endl << std::endl;
  std::cerr << "(the certificate list is expected to have the end-entity ";
  std::cerr << "certificate first, followed by one or more intermediates, ";
  std::cerr << "followed by the root certificate)" << std::endl;
  std::cerr << "If -d is specified (with an EV policy description), then ";
  std::cerr << argv0 << " will print out the information necessary to enable ";
  std::cerr << "the given root for EV treatment in Firefox. Otherwise, ";
  std::cerr << argv0 << " will simply print out 'Success!' or an error string ";
  std::cerr << "describing an encountered failure." << std::endl;
}

inline void
SECITEM_FreeItem_true(SECItem* item)
{
  SECITEM_FreeItem(item, true);
}

typedef mozilla::pkix::ScopedPtr<SECItem, SECITEM_FreeItem_true> ScopedSECItem;

CERTCertificate*
DecodeBase64Cert(const std::string& base64)
{
  size_t derLen = (base64.length() * 3) / 4;
  if (base64.length() < 2) {
    return nullptr;
  }
  if (base64[base64.length() - 1] == '=') {
    derLen--;
  }
  if (base64[base64.length() - 2] == '=') {
    derLen--;
  }
  ScopedSECItem der(SECITEM_AllocItem(nullptr, nullptr, derLen));
  if (!der) {
    PrintPRError("SECITEM_AllocItem failed");
    return nullptr;
  }
  if (!PL_Base64Decode(base64.data(), base64.length(),
                       reinterpret_cast<char*>(der->data))) {
    PrintPRError("PL_Base64Decode failed");
    return nullptr;
  }
  CERTCertificate* cert = CERT_NewTempCertificate(CERT_GetDefaultCertDB(),
                                                  der.get(), nullptr, false,
                                                  true);
  if (!cert) {
    PrintPRError("CERT_NewTempCertificate failed");
    return nullptr;
  }
  return cert;
}

static const char PEM_HEADER[] = "-----BEGIN CERTIFICATE-----";
static const char PEM_FOOTER[] = "-----END CERTIFICATE-----";

CERTCertList*
ReadCertsFromFile(const char* filename)
{
  CERTCertList* certs = CERT_NewCertList();
  if (!certs) {
    PrintPRError("CERT_NewCertList failed");
    return nullptr;
  }
  std::string currentPem;
  bool readingCertificate = false;
  std::ifstream file(filename);
  while (!file.eof()) {
    std::string line;
    std::getline(file, line);
    // getline appears to strip off '\n' but not '\r'
    // (maybe it's platform-dependent?)
    if (line.length() > 0 && line.back() == '\r') {
      line.pop_back();
    }
    if (line.compare(PEM_FOOTER) == 0) {
      readingCertificate = false;
      CERTCertificate* cert = DecodeBase64Cert(currentPem);
      if (cert) {
        if (CERT_AddCertToListTail(certs, cert) != SECSuccess) {
          PrintPRError("CERT_AddCertToListTail failed");
        }
      }
      currentPem.clear();
    }
    if (readingCertificate) {
      currentPem += line;
    }
    if (line.compare(PEM_HEADER) == 0) {
      readingCertificate = true;
    }
  }
  return certs;
}

typedef uint8_t SHA256Buffer[SHA256_LENGTH];

SECStatus
HashBytes(SHA256Buffer& output, const SECItem& data)
{
  if (PK11_HashBuf(SEC_OID_SHA256, output, data.data, data.len)
        != SECSuccess) {
    PrintPRError("PK11_HashBuf failed");
    return SECFailure;
  }
  return SECSuccess;
}

std::ostream&
HexPrint(std::ostream& output)
{
  output.fill('0');
  return output << "0x" << std::hex << std::uppercase << std::setw(2);
}

void
PrintSHA256HashOf(const SECItem& data)
{
  SHA256Buffer hash;
  if (HashBytes(hash, data) != SECSuccess) {
    return;
  }
  // The format is:
  // '{ <11 hex bytes>
  //    <11 hex bytes>
  //    <10 hex bytes> },'
  std::cout << "{ ";
  for (size_t i = 0; i < 11; i++) {
    uint32_t val = hash[i];
    std::cout << HexPrint << val << ", ";
  }
  std::cout << std::endl << "  ";
  for (size_t i = 11; i < 22; i++) {
    uint32_t val = hash[i];
    std::cout << HexPrint << val << ", ";
  }
  std::cout << std::endl << "  ";
  for (size_t i = 22; i < 31; i++) {
    uint32_t val = hash[i];
    std::cout << HexPrint << val << ", ";
  }
  uint32_t val = hash[31];
  std::cout << HexPrint << val << " }," << std::endl;
}

void
PrintBase64Of(const SECItem& data)
{
  std::string base64(PL_Base64Encode(reinterpret_cast<const char*>(data.data),
                                     data.len, nullptr));
  // The format is:
  // '"<base64>"
  //  "<base64>",'
  // where each line is limited to 64 characters of base64 data.
  size_t lines = base64.length() / 64;
  for (size_t line = 0; line < lines; line++) {
    std::cout << "\"" << base64.substr(64 * line, 64) << "\"" << std::endl;
  }
  size_t remainder = base64.length() % 64;
  std::cout << "\"" << base64.substr(base64.length() - remainder) << "\"," << std::endl;
}

typedef mozilla::pkix::ScopedPtr<PLOptState, PL_DestroyOptState>
  ScopedPLOptState;

int main(int argc, char* argv[]) {
  if (argc < 7) {
    PrintUsage(argv[0]);
    return 1;
  }
  if (NSS_NoDB_Init(nullptr) != SECSuccess) {
    PrintPRError("NSS_NoDB_Init failed");
  }
  const char* certsFileName = nullptr;
  const char* dottedOID = nullptr;
  const char* oidDescription = nullptr;
  const char* hostname = nullptr;
  ScopedPLOptState opt(PL_CreateOptState(argc, argv, "c:o:d:h:"));
  PLOptStatus os;
  while ((os = PL_GetNextOpt(opt.get())) != PL_OPT_EOL) {
    if (os == PL_OPT_BAD) {
      continue;
    }
    switch (opt->option) {
      case 'c':
        certsFileName = opt->value;
        break;
      case 'o':
        dottedOID = opt->value;
        break;
      case 'd':
        oidDescription = opt->value;
        break;
      case 'h':
        hostname = opt->value;
        break;
      default:
        PrintUsage(argv[0]);
        return 1;
    }
  }
  if (!certsFileName || !dottedOID || !hostname) {
    PrintUsage(argv[0]);
    return 1;
  }

  mozilla::pkix::RegisterErrorTable();

  ScopedCERTCertList certs(ReadCertsFromFile(certsFileName));
  if (CERT_LIST_END(CERT_LIST_HEAD(certs), certs)) {
    std::cerr << "Couldn't read certificates from '" << certsFileName << "'";
    std::cerr << std::endl;
    return 1;
  }
  CERTCertificate* root = CERT_LIST_TAIL(certs.get())->cert;
  CERTCertificate* ee = CERT_LIST_HEAD(certs.get())->cert;
  if (oidDescription) {
    std::cout << "// " << root->subjectName << std::endl;
    std::cout << "\"" << dottedOID << "\"," << std::endl;
    std::cout << "\"" << oidDescription << "\"," << std::endl;
    PrintSHA256HashOf(root->derCert);
    PrintBase64Of(root->derIssuer);
    PrintBase64Of(root->serialNumber);
  }
  EVCheckerTrustDomain trustDomain(CERT_DupCertificate(root));
  if (trustDomain.Init(dottedOID, oidDescription) != SECSuccess) {
    return 1;
  }
  ScopedCERTCertList results;
  mozilla::pkix::CertPolicyId evPolicy;
  if (trustDomain.GetFirstEVPolicyForCert(ee, evPolicy)
        != SECSuccess) {
    PrintPRError("GetFirstEVPolicyForCert failed");
    std::cerr << "This may mean that the specified EV Policy OID was not ";
    std::cerr << "found in the end-entity certificate." << std::endl;
    return 1;
  }
  mozilla::pkix::Input eeInput;
  mozilla::pkix::Result rv = eeInput.Init(ee->derCert.data, ee->derCert.len);
  if (rv != mozilla::pkix::Success) {
    std::cerr << "Couldn't initialize Input from ee cert" << std::endl;
    return 1;
  }
  rv = BuildCertChain(trustDomain, eeInput, mozilla::pkix::Now(),
                      mozilla::pkix::EndEntityOrCA::MustBeEndEntity,
                      mozilla::pkix::KeyUsage::noParticularKeyUsageRequired,
                      mozilla::pkix::KeyPurposeId::anyExtendedKeyUsage,
                      evPolicy, nullptr);
  if (rv != mozilla::pkix::Success) {
    PR_SetError(mozilla::pkix::MapResultToPRErrorCode(rv), 0);
    PrintPRError("BuildCertChain failed");
    PrintPRErrorString();
    if (rv == mozilla::pkix::Result::ERROR_POLICY_VALIDATION_FAILED) {
      std::cerr << "It appears be the case that the end-entity certificate ";
      std::cerr << "was issued directly by the root. There should be at ";
      std::cerr << "least one intermediate in the certificate issuance chain.";
      std::cerr << std::endl;
    } else if (rv == mozilla::pkix::Result::ERROR_CERT_BAD_ACCESS_LOCATION) {
      std::cerr << "It appears to be the case that a certificate in the ";
      std::cerr << "issuance chain has a malformed or missing OCSP AIA URI";
      std::cerr << std::endl;
    }
    return 1;
  }

  mozilla::pkix::Input hostnameInput;
  rv = hostnameInput.Init(reinterpret_cast<const uint8_t*>(hostname),
                          strlen(hostname));
  if (rv != mozilla::pkix::Success) {
    PrintPRError("Couldn't initialize Input from hostname");
    return 1;
  }
  rv = CheckCertHostname(eeInput, hostnameInput);
  if (rv != mozilla::pkix::Success) {
    PR_SetError(mozilla::pkix::MapResultToPRErrorCode(rv), 0);
    PrintPRError("CheckCertHostname failed");
    PrintPRErrorString();
    if (rv == mozilla::pkix::Result::ERROR_BAD_CERT_DOMAIN) {
      std::cerr << "It appears that the end-entity certificate is not valid ";
      std::cerr << "for the domain it is hosted at.";
      std::cerr << std::endl;
    } else if (rv == mozilla::pkix::Result::ERROR_BAD_DER) {
      std::cerr << "It appears that the name information in the end-entity ";
      std::cerr << "certificate does not conform to RFC 822, RFC 5280, or ";
      std::cerr << "RFC 6125.";
      std::cerr << std::endl;
    }
    return 1;
  }

  std::cout << "Success!" << std::endl;
  return 0;
}
