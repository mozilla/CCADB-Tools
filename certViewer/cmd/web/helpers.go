/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"os"
	"runtime/debug"
)

func (app *application) serverError(w http.ResponseWriter, r *http.Request, err error) {
	var (
		method = r.Method
		uri    = r.URL.RequestURI()
		trace  = string(debug.Stack())
	)

	app.logger.Error(err.Error(), "method", method, "uri", uri, "trace", trace)

	http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
}

func (app *application) clientError(w http.ResponseWriter, status int) {
	http.Error(w, http.StatusText(status), status)
}

func (app *application) notFound(w http.ResponseWriter) {
	app.clientError(w, http.StatusNotFound)
}

func (app *application) render(w http.ResponseWriter, r *http.Request, status int, page string, data templateData) {
	ts, ok := app.templateCache[page]
	if !ok {
		err := fmt.Errorf("the template %s does not exist", page)
		app.serverError(w, r, err)
		return
	}

	buf := new(bytes.Buffer)

	err := ts.ExecuteTemplate(buf, "base", data)
	if err != nil {
		app.serverError(w, r, err)
		return
	}

	w.WriteHeader(status)

	buf.WriteTo(w)
}

func (app *application) newTemplateData(r *http.Request) templateData {
	return templateData{}
}

// uploadSave handles the process of saving an uploaded file to the file system
func (app *application) uploadSave(r *http.Request) string {
	err := r.ParseMultipartForm(1 << 20)
	if err != nil {
		app.logger.Error("Unable to parse form", "error", err.Error())
	}

	file, fileHeader, err := r.FormFile("rootCertUpload")
	if err != nil {
		app.logger.Error("Unable to parse form", "error", err.Error())
	}
	defer file.Close()

	err = os.MkdirAll("/tmp", os.ModePerm)
	if err != nil {
		app.logger.Error("Unable to create /tmp directory", "error", err.Error())
	}

	pemFile := "/tmp/" + fileHeader.Filename
	dst, err := os.Create(pemFile)
	if err != nil {
		app.logger.Error("Unable to create file", "error", err.Error())
	}

	defer dst.Close()

	if _, err := io.Copy(dst, file); err != nil {
		app.logger.Error("Unable to save file", "error", err.Error())
	}

	return pemFile
}

// pemReader reads the contents of a PEM file
func (app *application) pemReader(pemUpload string) string {
	content, err := os.ReadFile(pemUpload)
	if err != nil {
		app.logger.Error("Unable to read contents of uploaded file", "error", err.Error())
	}

	return string(content)
}
