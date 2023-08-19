/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <iostream>

#include "Util.h"

#include "prerror.h"

void
PrintPRError(const char* message)
{
  const char* err = PR_ErrorToName(PR_GetError());
  if (err) {
    std::cerr << message << ": " << err << std::endl;
  } else {
    std::cerr << message << std::endl;
  }
}

void
PrintPRErrorString()
{
  std::cerr << PR_ErrorToString(PR_GetError(), 0) << std::endl;
}


void
PrintEVError(const char* message)
{
  std::cerr << message << std::endl;
}
