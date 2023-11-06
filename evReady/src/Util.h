/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#ifndef Util_h
#define Util_h

#include "pkix/pkixtypes.h"
#include "pkix/ScopedPtr.h"

#include "cert.h"

inline void
PORT_FreeArena_false(PLArenaPool* arena)
{
  return PORT_FreeArena(arena, false);
}

typedef mozilla::pkix::ScopedPtr<CERTCertificate, CERT_DestroyCertificate>
  ScopedCERTCertificate;
typedef mozilla::pkix::ScopedPtr<CERTCertList, CERT_DestroyCertList>
  ScopedCERTCertList;
typedef mozilla::pkix::ScopedPtr<PLArenaPool, PORT_FreeArena_false>
  ScopedPLArenaPool;

void PrintPRError(const char* message);
void PrintPRErrorString();
void PrintEVError(const char* message);

inline void
PortFreeString(const char* ptr)
{
  PORT_Free((void*)ptr);
}
typedef mozilla::pkix::ScopedPtr<const char, PortFreeString> ScopedString;

#endif // Util_h
