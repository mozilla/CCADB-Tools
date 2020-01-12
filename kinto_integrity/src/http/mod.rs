/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use reqwest::Url;

// Mozilla ops kindly asks tooling authors to declare their calls as being X-AUTOMATED-TOOL
// as well as let them know where to find the code that is hitting them via the user agent header.
const USER_AGENT_VALUE: &str =
    "github.com/mozilla/CCADB-Tools/kinto_integrity chris@chenderson.org";
const X_AUTOMATED_TOOL_KEY: &str = "X-Automated-Tool";
const X_AUTOMATED_TOOL_VALUE: &str = "github.com/mozilla/CCADB-Tools/kinto_integrity";

pub fn new_get_request(url: Url) -> reqwest::blocking::RequestBuilder {
    reqwest::blocking::Client::new()
        .get(url)
        .header(reqwest::header::USER_AGENT, USER_AGENT_VALUE)
        .header(X_AUTOMATED_TOOL_KEY, X_AUTOMATED_TOOL_VALUE)
}
