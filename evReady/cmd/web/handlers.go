/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"net/http"
	"os/exec"
	"strings"

	"github.com/mozilla/CCADB-Tools/evReady/internal/validator"
)

type evForm struct {
	Hostname string
	OID      string
	RootCert string
	//RootCertFile *multipart.FileHeader
	Status string
	validator.Validator
}

func (app *application) home(w http.ResponseWriter, r *http.Request) {
	data := app.newTemplateData(r)
	data.Form = evForm{}

	app.render(w, r, http.StatusOK, "home.tmpl", data)

}

func (app *application) evcheck(w http.ResponseWriter, r *http.Request) {
	err := r.ParseForm()
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	form := evForm{
		Hostname: r.PostForm.Get("hostname"),
		OID:      r.PostForm.Get("oid"),
		RootCert: r.PostForm.Get("rootCert"),
	}

	form.CheckField(validator.NotBlank(form.Hostname), "hostname", "Hostname field is required")
	form.CheckField(validator.MaxChars(form.Hostname, 253), "hostname", "Hostname cannot be more than 253 characters")
	form.CheckField(validator.ValidURL(form.Hostname), "hostname", "Hostname must be in a valid URL format with no spaces")
	form.CheckField(validator.NotBlank(form.OID), "oid", "OID field is required")
	form.CheckField(validator.MaxChars(form.OID, 253), "oid", "OID cannot be more than 253 characters")
	form.CheckField(validator.ValidOID(form.OID), "oid", "OID must be a valid OID format")
	form.CheckField(validator.NotBlank(form.RootCert), "rootCert", "PEM certificate field is required")
	form.CheckField(validator.ValidPEMPaste(form.RootCert), "rootCert", "Certificate must be PEM-encoded")

	if !form.Valid() {
		data := app.newTemplateData(r)
		data.Form = form
		app.render(w, r, http.StatusUnprocessableEntity, "home.tmpl", data)
		return
	}

	hostname := app.urlCleaner(strings.TrimSpace(form.Hostname))
	oid := strings.TrimSpace(form.OID)

	pemFile, err := app.pemCreator(form.Hostname, form.RootCert)
	if err != nil {
		app.logger.Error("Unable to write pasted PEM contents to disk.", "error", err.Error())
	}

	out, err := exec.Command(evReadyExec, "-h", hostname, "-o", oid, "-c", pemFile).CombinedOutput()
	if err != nil {
		app.logger.Error("ev-ready exec failed", "Error", err.Error())
	}

	app.logger.Info("Ran ev-checker", "Status", string(out))
	flash := string(out)

	data := app.newTemplateData(r)
	data.Form = form
	data.Flash = flash
	app.render(w, r, http.StatusOK, "home.tmpl", data)

	app.certCleanup(pemFile)
}
