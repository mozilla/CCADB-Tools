/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// checkEvReadyExecExists checks if the executable is present -- if it's not, exit,
// because it's the brains behind everything
func checkEvReadyExecExists(path string) {
	path, err := exec.LookPath(path)
	if err != nil {
		slog.Error("ev-ready executable not found... exiting.")
		os.Exit(127)
	}
}

// hostnameValidator validates and cleans up the entered hostname
func hostnameValidator(hostname string) string {
	u, err := url.Parse(strings.TrimSpace(hostname))
	if err != nil {
		slog.Error("Unable to parse hostname url.", "Error", err.Error())
	}
	if u.IsAbs() {
		return u.Hostname()
	} else {
		return strings.TrimSuffix(u.Path, "/")
	}
}

// oidValidator validates and cleans up the entered OID
func oidValidator(oid string) bool {
	re := regexp.MustCompile(`^([0-2])((\.0)|(\.[1-9][0-9]*))*$`)

	return re.MatchString(strings.TrimSpace(oid))
}

// pemValidator validates and cleans up the pasted PEM content
func pemValidator(pem string) bool {
	pem = strings.TrimSpace(pem)
	return strings.HasPrefix(pem, "-----BEGIN CERTIFICATE-----") &&
		strings.HasSuffix(pem, "-----END CERTIFICATE-----")
}
