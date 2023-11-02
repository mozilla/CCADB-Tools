/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"github.com/mozilla/CCADB-Tools/evReady/internal/validator"
	"net/http"
	"os/exec"
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
	form.CheckField(validator.NotBlank(form.OID), "oid", "OID field is required")
	form.CheckField(validator.MaxChars(form.OID, 253), "oid", "OID cannot be more than 253 characters")
	form.CheckField(validator.NotBlank(form.RootCert), "rootCert", "A PEM-encoded certificate is required")

	if !form.Valid() {
		data := app.newTemplateData(r)
		data.Form = form
		app.render(w, r, http.StatusUnprocessableEntity, "home.tmpl", data)
		return
	}

	pemFile, err := app.pemCreator(form.Hostname, form.RootCert)
	if err != nil {
		app.logger.Error("Unable to write pasted PEM contents to disk.", "error", err.Error())
	}

	out, err := exec.Command(evReadyExec, "-h", form.Hostname, "-o", form.OID, "-c", pemFile).CombinedOutput()
	if err != nil {
		app.logger.Error("ev-ready exec failed", "Error", err.Error())
	}

	app.logger.Info("Ran ev-checker", "Status", string(out))
	flash := string(out)

	data := app.newTemplateData(r)
	data.Form = form
	data.Flash = flash
	app.render(w, r, http.StatusOK, "home.tmpl", data)
	//file, header, err := r.FormFile("rootCertUpload")
	//if err != nil {
	//	app.clientError(w, http.StatusInternalServerError)
	//	return
	//}
	//defer file.Close()
	//
	//pemFile := "/tmp" + xid.New().String() + header.Filename

	app.certCleanup(pemFile)
}
