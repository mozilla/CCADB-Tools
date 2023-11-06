/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"flag"
	"html/template"
	"log/slog"
	"net/http"
	"os"
)

// executable built during the docker build step
const evReadyExec = "/app/ev-checker"

type application struct {
	logger        *slog.Logger
	pemFile       string
	templateCache map[string]*template.Template
	Request       *http.Request
}

func main() {
	// Default to port 8080 if PORT env var is not set
	port := getPortEnv("PORT", "8080")

	addr := flag.String("addr", ":"+port, "HTTP network address")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	templateCache, err := newTemplateCache()
	if err != nil {
		logger.Error(err.Error())
		os.Exit(1)
	}

	app := &application{
		logger:        logger,
		templateCache: templateCache,
	}

	logger.Info("starting server", "addr", *addr)

	// Check for ev-checker binary
	checkEvReadyExecExists(evReadyExec)

	err = http.ListenAndServe(*addr, app.routes())
	logger.Error(err.Error())
	os.Exit(1)
}

// getPortEnv looks for the PORT env var and uses fallback if not set
func getPortEnv(port, fallback string) string {
	if value, ok := os.LookupEnv(port); ok {
		return value
	}
	return fallback
}
