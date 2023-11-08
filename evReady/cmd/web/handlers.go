/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"mime/multipart"
	"net/http"
	"os/exec"
	"strings"

	"github.com/mozilla/CCADB-Tools/evReady/internal/validator"
)

type evForm struct {
	Hostname       string
	OID            string
	RootCert       string
	RootCertUpload *multipart.FileHeader
	Status         string
	validator.Validator
}

// home handles the default endpoint GET request, "/evready"
func (app *application) home(w http.ResponseWriter, r *http.Request) {
	data := app.newTemplateData(r)
	data.Form = evForm{}

	app.render(w, r, http.StatusOK, "home.tmpl", data)

}

// evcheck handles the form POST request from the "/evready" endpoint
func (app *application) evcheck(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(1 << 20) // 10MB
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	form := evForm{
		Hostname: r.PostFormValue("hostname"),
		OID:      r.PostFormValue("oid"),
		RootCert: r.PostFormValue("rootCert"),
	}

	_, header, _ := r.FormFile("rootCertUpload")
	form.RootCertUpload = header

	form.CheckField(validator.NotBlank(form.Hostname), "hostname", "Hostname field is required")
	form.CheckField(validator.MaxChars(form.Hostname, 253), "hostname", "Hostname cannot be more than 253 characters")
	form.CheckField(validator.ValidURL(form.Hostname), "hostname", "Hostname must be in a valid URL format with no spaces")
	form.CheckField(validator.NotBlank(form.OID), "oid", "OID field is required")
	form.CheckField(validator.MaxChars(form.OID, 253), "oid", "OID cannot be more than 253 characters")
	form.CheckField(validator.ValidOID(form.OID), "oid", "OID must be a valid OID format")
	form.CheckField(validator.NoPEMs(form.RootCert, form.RootCertUpload), "rootCertUpload", "Please upload or paste the contents of a PEM file")
	form.CheckField(validator.BothPEMs(form.RootCert, form.RootCertUpload), "rootCertUpload", "Please only submit a pasted PEM file OR upload a file")

	hostname := app.urlCleaner(form.Hostname)
	oid := strings.TrimSpace(form.OID)

	var pemFile string

	if form.RootCert != "" {
		form.CheckField(validator.ValidPEM(form.RootCert), "rootCert", "Invalid certificate format. Certificate must be PEM-encoded")
		pemFile, err = app.pemCreator(hostname, form.RootCert)
		if err != nil {
			app.logger.Error("Unable to create PEM file from pasted contents", "Error", err.Error())
		}
	} else if form.RootCertUpload != nil {
		pemUploadFile := app.pemReader(app.uploadSave(r))
		form.CheckField(validator.ValidPEM(pemUploadFile), "rootCertUpload", "Invalid certificate format. Certificate must be PEM-encoded")
		pemFile, err = app.pemCreator(hostname, pemUploadFile)
		if err != nil {
			app.logger.Error("Unable to create PEM file from upload", "Error", err.Error())
		}
	}

	if !form.Valid() {
		data := app.newTemplateData(r)
		data.Form = form
		app.render(w, r, http.StatusUnprocessableEntity, "home.tmpl", data)
		return
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

	// remove the cert written to the file system
	app.certCleanup(pemFile)
}
