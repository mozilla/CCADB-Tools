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
	Status         string
}

// evReady handles the GET /evready endpoint
func evReady(c *gin.Context) {
	c.HTML(http.StatusOK, "base", gin.H{
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
	slog.Info("Hostname received", "Hostname", ev.Hostname)
	if ev.Hostname == "" {
		c.HTML(
			http.StatusBadRequest,
			"base",
			gin.H{
				"Error": "Error: Hostname required.",
			})
		return
	}

	ev.OID = c.PostForm("oid")
	slog.Info("OID received", "OID", ev.OID)
	// Use oidValidator to validate and clean up OIDs
	if ev.OID == "" {
		c.HTML(
			http.StatusBadRequest,
			"base",
			gin.H{
				"Error": "Error: OID required.",
			})
		return
	}
	if oidValidator(ev.OID) == false {
		slog.Error("Invalid OID format.")
		c.HTML(
			http.StatusBadRequest,
			"base",
			gin.H{
				"Error": "Error: Invalid OID format. Please refer to <a href=https://www.ietf.org/rfc/rfc3001.txt>https://www.ietf.org/rfc/rfc3001.txt</a>",
			})
		return
	}

	var certFile string
	var err error
	ev.RootCert = c.PostForm("rootCertificate")
	ev.RootCertUpload, err = c.FormFile("rootCertUpload")

	// Check for both an uploaded PEM file and pasted PEM -- if both were submitted,
	// let user know to only submit one. And if not file, use the pasted PEM contents
	if ev.RootCert == "" && ev.RootCertUpload == nil {
		c.HTML(
			http.StatusBadRequest,
			"base",
			gin.H{
				"Error": "Error: Please upload or paste the contents of a PEM file.",
			})
		return
	} else if ev.RootCert != "" && ev.RootCertUpload != nil {
		c.HTML(
			http.StatusBadRequest,
			"base",
			gin.H{
				"Error": "Error: Please only submit a pasted PEM file OR upload a file.",
			})
		return
	} else if ev.RootCertUpload != nil && err != nil {
		slog.Error("Get form file error.", "Error", err.Error())
		c.HTML(
			http.StatusBadRequest,
			"base",
			gin.H{
				"Error": "Error: Get form file error: %s",
			})
		return
	} else if ev.RootCertUpload != nil {
		// Put uploaded PEM file in a guid-generated directory for safety
		pemFile := path + "/" + ev.RootCertUpload.Filename
		if err := c.SaveUploadedFile(ev.RootCertUpload, pemFile); err != nil {
			slog.Error("Upload file error.", "Error", err.Error())
			c.HTML(
				http.StatusBadRequest,
				"base",
				gin.H{
					"Error": "Error: Upload file error.",
				})
			return
		}
		// Open the uploaded file
		rootCertFileContent, err := ev.RootCertUpload.Open()
		if err != nil {
			slog.Error("Unable to open uploaded PEM file.", "Error", err.Error())
			c.HTML(
				http.StatusBadRequest,
				"base",
				gin.H{
					"Error": "Error: Unable to open uploaded PEM file.",
				})
			return
		}
		// Reads the content of the file
		decodedCertFile, err := io.ReadAll(rootCertFileContent)
		if err != nil {
			slog.Error("Unable to decode PEM file.", "Error", err.Error())
			c.HTML(
				http.StatusBadRequest,
				"base",
				gin.H{
					"Error": "Error: Unable to decode PEM file.",
				})
			return
		}
		// Use pemValidator to validate and clean up PEM file content
		if pemValidator(string(decodedCertFile)) == false {
			slog.Error("Invalid certificate format. Must be PEM encoded.")
			c.HTML(
				http.StatusBadRequest,
				"base",
				gin.H{
					"Error": "Error: Invalid certificate format. Must be PEM encoded.",
				})
			return
		}
		certFile, err = handleCert(ev.Hostname, string(decodedCertFile))
		if err != nil {
			slog.Error("Unable to write uploaded PEM file to disk.", "Error", err.Error())
		}
	} else if ev.RootCert != "" && pemValidator(ev.RootCert) == false {
		slog.Error("Invalid certificate format. Must be PEM encoded.")
		c.HTML(
			http.StatusBadRequest,
			"base",
			gin.H{
				"Error": "Error: Invalid certificate format. Must be PEM encoded.",
			})
		return
	} else if ev.RootCert != "" {
		certFile, err = handleCert(ev.Hostname, ev.RootCert)
		if err != nil {
			slog.Error("Unable to write pasted PEM contents to disk.", "Error", err.Error())
		}
	}

	// Run ev-checker executable
	out, err := exec.Command(evReadyExec, "-h", ev.Hostname, "-o", ev.OID, "-c", certFile).CombinedOutput()
	if err != nil {
		slog.Error("ev-ready exec failed", "Error", err.Error())
	}

	slog.Info("Ran ev-checker", "Status", string(out))
	ev.Status = string(out)
	c.HTML(
		http.StatusOK,
		"base",
		gin.H{
			"Status": "EV readiness status: " + ev.Status,
		},
	)

	// Clean up files written for evaluation
	removeErr := os.RemoveAll(certFile)
	if removeErr != nil {
		slog.Error("Unable to delete PEM files or directories", "Error", err.Error())
	} else {
		slog.Info("Removed unused PEM file", "File", certFile)
	}
}
