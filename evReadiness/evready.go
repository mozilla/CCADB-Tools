/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"github.com/gin-gonic/gin"
	"github.com/rs/xid"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
)

type evForm struct {
	Hostname       string                `form:"hostname" binding:"required"`
	OID            string                `form:"oid" binding:"required"`
	RootCert       string                `form:"rootCertificate" binding:"omitempty"`
	RootCertUpload *multipart.FileHeader `form:"rootCertUpload" binding:"omitempty"`
}

// evReady handles the GET /evready endpoint
func evReady(c *gin.Context) {
	c.HTML(http.StatusOK, "evready", gin.H{
		"title": "EV Readiness",
	})
}

// evReadyPost handles the POST /evready endpoint
func evReadyPost(c *gin.Context) {
	// Generate a guid to prevent filename conflicts in the case of simulataneous uploads or PEM checks
	guid := xid.New()
	path := "/tmp/" + guid.String()

	var ev evForm
	c.Bind(&ev)

	// Use hostnameValidator to validate and clean up hostnames
	ev.Hostname = hostnameValidator(c.PostForm("hostname"))
	slog.Info("Received: ", "Hostname", ev.Hostname)

	ev.OID = c.PostForm("oid")
	slog.Info("Received: ", "OID", ev.OID)
	// Use oidValidator to validate and clean up OIDs
	if oidValidator(ev.OID) == false {
		slog.Error("Invalid OID format.")
		c.String(http.StatusBadRequest, "Invalid OID format. Please refer to <a href=https://www.ietf.org/rfc/rfc3001.txt>https://www.ietf.org/rfc/rfc3001.txt</a>")
	}

	ev.RootCert = c.PostForm("rootCertificate")
	// Only run the pasted PEM validation/cleanup if it was submittted
	if ev.RootCert != "" && pemValidator(ev.RootCert) == false {
		slog.Error("Invalid certificate format. Must be PEM encoded.")
		c.String(http.StatusBadRequest, "Invalid certificate format. Must be PEM encoded.")
		return
	}

	var err error
	ev.RootCertUpload, err = c.FormFile("rootCertUpload")
	// Only check the PEM file if one was submitted
	if ev.RootCertUpload != nil && err != nil {
		slog.Error("Get form file error.", "Error", err.Error())
		c.String(http.StatusBadRequest, "Get form file error: %s", err.Error())
		return
	}

	var certFile string
	// Check for an uploaded PEM file -- if one wasn't submitted, use the pasted PEM contents
	if ev.RootCertUpload != nil {
		// Put uploaded PEM file in a guid-generated directory for safety
		pemFile := path + "/" + ev.RootCertUpload.Filename
		if err := c.SaveUploadedFile(ev.RootCertUpload, pemFile); err != nil {
			slog.Error("Upload file error.", "Error", err.Error())
			c.String(http.StatusBadRequest, "Upload file error: %s", err.Error())
			return
		}
		// Open the uploaded file
		rootCertFileContent, err := ev.RootCertUpload.Open()
		if err != nil {
			slog.Error("Unable to open uploaded PEM file.", "Error", err.Error())
			c.String(http.StatusBadRequest, "Unable to open uploaded PEM file: %s", err.Error())
			return
		}
		// Reads the content of the file
		decodedCertFile, err := io.ReadAll(rootCertFileContent)
		if err != nil {
			slog.Error("Unable to decode PEM file.", "Error", err.Error())
			c.String(http.StatusBadRequest, "Unable to decode PEM file: %s", err.Error())
			return
		}
		// Use pemValidator to validate and clean up PEM file content
		if pemValidator(string(decodedCertFile)) == false {
			slog.Error("Invalid certificate format. Must be PEM encoded.")
			c.String(http.StatusBadRequest, "Invalid certificate format. Must be PEM encoded.")
		}
		certFile, err = handleCert(ev.Hostname, string(decodedCertFile))
		if err != nil {
			slog.Error("Unable to write uploaded PEM file to disk.", "Error", err.Error())
		}
	} else {
		certFile, err = handleCert(ev.Hostname, ev.RootCert)
		if err != nil {
			slog.Error("Unable to write pasted PEM contents to disk.", "Error", err.Error())
		}
	}

	data, err := os.ReadFile(certFile)
	if err != nil {
		slog.Error("Unable to read certFile.", "Error", err.Error())
	}
	slog.Info("certFile read...", "Contents", string(data))

	// Run ev-checker executable
	out, err := exec.Command(evReadyExec, "-h", ev.Hostname, "-o", ev.OID, "-c", certFile).CombinedOutput()
	if err != nil {
		slog.Error("ev-ready exec failed", "Error", err.Error())
	}

	slog.Info("Successful!", "Status", string(out))
	c.String(http.StatusOK, "Status: %s", string(out))

	// Clean up files written for evaluation
	removeErr := os.RemoveAll(certFile)
	if removeErr != nil {
		slog.Error("Unable to delete PEM files or directories", "Error", err.Error())
	} else {
		slog.Info("Removed unused PEM file", "File", path)
	}
}
