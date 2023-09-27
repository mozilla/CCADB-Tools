/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at http://mozilla.org/MPL/2.0/. */

package main

import (
	"github.com/gin-gonic/gin"
	slogger "github.com/samber/slog-gin"
	"log/slog"
	"os"
)

// executable built during the docker build step
const evReadyExec = "/app/ev-checker"

func main() {
	// Use Go 1.21's log/slog structured logger
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)

	// ReleaseMode is for production -- no debugging
	gin.SetMode(gin.ReleaseMode)

	// Default to port 8080 if PORT env var is not set
	port := getPortEnv("PORT", "8080")

	router := gin.New()
	router.Use(slogger.New(logger))

	// Check for ev-checker binary
	checkEvReadyExecExists(evReadyExec)
	router.MaxMultipartMemory = 8 << 20
	router.LoadHTMLGlob("templates/*")
	router.Static("/static", "./static")
	router.GET("/evready", evReady)
	router.POST("/evready", evReadyPost)
	err := router.Run(":" + port)
	if err != nil {
		return
	}
}

// getPortEnv looks for the PORT env var and uses fallback if not set
func getPortEnv(port, fallback string) string {
	if value, ok := os.LookupEnv(port); ok {
		return value
	}
	return fallback
}
