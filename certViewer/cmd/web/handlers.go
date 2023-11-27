/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"crypto/x509"
	"encoding/pem"
	"github.com/mozilla/CCADB-Tools/certViewer/internal/validator"
	"mime/multipart"
	"net/http"
)

type certForm struct {
	RootCert       string
	RootCertUpload *multipart.FileHeader
	validator.Validator
}

// home handles the default endpoint GET request, "/certviewer"
func (app *application) home(w http.ResponseWriter, r *http.Request) {
	data := app.newTemplateData(r)
	data.Certificate = Certificate{
		Serial: "",
	}
	data.Form = certForm{}

	app.render(w, r, http.StatusOK, "home.tmpl", data)

}

// certPost handles the form POST request from the "/certviewer" endpoint
func (app *application) certPost(w http.ResponseWriter, r *http.Request) {
	err := r.ParseMultipartForm(1 << 20) // 10MB
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	form := certForm{
		RootCert: r.PostFormValue("rootCert"),
	}

	_, header, _ := r.FormFile("rootCertUpload")
	form.RootCertUpload = header

	form.CheckField(validator.NoPEMs(form.RootCert, form.RootCertUpload), "rootCertUpload", "Please upload or paste the contents of a PEM file")
	form.CheckField(validator.BothPEMs(form.RootCert, form.RootCertUpload), "rootCertUpload", "Please only submit a pasted PEM file OR upload a file")

	var pemFile string

	if form.RootCert != "" {
		form.CheckField(validator.ValidPEM(form.RootCert), "rootCert", "Invalid certificate format. Certificate must be PEM-encoded")
		pemFile = form.RootCert
	} else if form.RootCertUpload != nil {
		pemUploadFile := app.uploadSave(r)
		pemContents := app.pemReader(pemUploadFile)
		form.CheckField(validator.ValidPEM(pemContents), "rootCertUpload", "Invalid certificate format. Certificate must be PEM-encoded")
		pemFile = pemContents

		// remove the cert written to the file system
		app.certCleanup(pemUploadFile)
	}

	if !form.Valid() {
		data := app.newTemplateData(r)
		data.Form = form
		app.render(w, r, http.StatusUnprocessableEntity, "home.tmpl", data)
		return
	}

	block, _ := pem.Decode([]byte(pemFile))
	if block == nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	certX509, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		app.clientError(w, http.StatusBadRequest)
		return
	}

	certData := certInfo(certX509)
	data := app.newTemplateData(r)
	data.Certificate = certData
	data.Form = form

	app.render(w, r, http.StatusOK, "home.tmpl", data)
}
