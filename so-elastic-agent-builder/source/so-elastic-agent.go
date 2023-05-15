// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0; you may not use
// this file except in compliance with the Elastic License 2.0.

package main

import (
	"context"
	"crypto/tls"
	_ "embed"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/apex/log"
	"github.com/apex/log/handlers/logfmt"
	"github.com/apex/log/handlers/text"
	"github.com/mholt/archiver/v3"
)

//go:embed files/cert/intca.crt
var caCRT []byte

var fleetHostURLsList = ""
var fleetHostFlag string

var enrollmentToken, enrollmentTokenFlag string

func check(err error, context string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n\n%s: %v\n", context, err)
		log.WithFields(log.Fields{
			"Context":       context,
			"Error Details": err,
		}).Error("Installation Progress")
		cleanupInstall()
		os.Exit(1)
	}
}

func cleanupInstall() {
	err := os.Remove("./so-elastic-agent_source.tar.gz")
	if err != nil {
		log.WithFields(log.Fields{
			"Context":       "Unable to delete so-elastic-agent_source.tar.gz - it can be deleted manually.",
			"Error Details": err,
		}).Error("Installation Progress")
	}

	err = os.RemoveAll("./so-elastic-agent_source")
	if err != nil {
		log.WithFields(log.Fields{
			"Context":       "Unable to delete so-elastic-agent_source folder - it can be deleted manually.",
			"Error Details": err,
		}).Error("Installation Progress")
	}
}

func statusLogs(status string) {
	log.WithFields(log.Fields{
		"Status": status,
	}).Info("Installation Progress")
}

func InitLogging(logFilename string, logLevel string) (*os.File, error) {
	logFile, err := os.OpenFile(logFilename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)
	if err == nil {
		log.SetHandler(logfmt.New(logFile))
	} else {
		log.WithError(err).WithField("logfile", logFilename).Error("Failed to create log file, using console only")
		log.SetHandler(text.New(os.Stdout))
	}
	log.SetLevelFromString(logLevel)
	return logFile, err
}

func main() {

	fmt.Println("\nInstallation initiated, view install log for further details.")

	logFile, _ := InitLogging("SO-Elastic-Agent_Installer.log", "info")
	defer logFile.Close()

	log.WithFields(log.Fields{
		"Wrapper Version":       "2.4.2",
		"Elastic Agent Version": "8.7.0",
	}).Info("Version Information")

	// Allow runtime configuration
	flag.StringVar(&enrollmentTokenFlag, "token", "", "Override default Enrollment Token")
	flag.StringVar(&fleetHostFlag, "fleet", "", "Override default Fleet Host")
	flag.Parse()

	if enrollmentTokenFlag != "" {
		enrollmentToken = enrollmentTokenFlag
	}

	if fleetHostFlag != "" {
		fleetHostURLsList = fleetHostFlag
	}

	log.WithFields(log.Fields{
		"Fleet URL/s":      fleetHostURLsList,
		"Enrollment Token": enrollmentToken,
	}).Info("Runtime Data")

	statusLogs("Starting Installation Precheck")

	// Check to make sure that control plane is accessible

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}

	fleetHostURLs := strings.Split(fleetHostURLsList, ",")
	var fleetURLReachable bool
	var fleetHostURL = ""
	// Iterate through Fleet Host URLs - the first one that responds will be used for enrollment
	for i := 0; i < len(fleetHostURLs); i++ {

		req, err := http.NewRequest("GET", fleetHostURLs[i], nil)
		check(err, "Error creating constructing FleetHostURL HTTP Request")

		resp, err := client.Do(req)

		if (err != nil) || (resp.StatusCode != http.StatusNotFound) {
			// Cannot access Fleet Host URL
			fmt.Println("Not Accessible")
			log.WithFields(log.Fields{
				"Fleet Host Connectivity Check": "Failed",
				"Fleet Host URL":                fleetHostURLs[i],
			}).Warn("Installation Progress")

		} else {
			// Break out of loop here and use this fleetURL for enrollment
			log.WithFields(log.Fields{
				"Fleet Host Connectivity Check": "Success",
				"Fleet Host URL":                fleetHostURLs[i],
			}).Info("Installation Progress")
			fleetHostURL = fleetHostURLs[i]
			fleetURLReachable = true
			break
		}
	}

	if fleetURLReachable {
		statusLogs("Fleet Host is accessible - Continuing installation")
	} else {
		statusLogs("No Fleet Hosts are accessible - Check connectivity to Fleet Host.")
		statusLogs("Exiting Installer...")
		os.Exit(1)
	}

	statusLogs("Installation Precheck Complete")

	statusLogs("Extracting Elastic Agent files")

	// Create Elastic Agent install dir & copy SO CA Cert to it
	crtPath := installPath + "soca.crt"

	err := os.MkdirAll(installPath, 0755)
	check(err, "Error creating Elastic Agent directories.")

	err = os.WriteFile(crtPath, caCRT, 0755)
	check(err, "Error copying over the SO ca.crt.")

	// Copy over embedded tar & extract it to the local system
	_ = os.WriteFile("so-elastic-agent_source.tar.gz", agentFiles, 0755)
	err = archiver.Unarchive("./so-elastic-agent_source.tar.gz", "so-elastic-agent_source")
	check(err, "Error extracting Elastic Agent source.")

	// Install Elastic Agent
	statusLogs("Executing Elastic Agent installer")
	prg := "./so-elastic-agent_source/elastic-agent/elastic-agent"

	arg1 := "install"
	arg2 := "--url=" + fleetHostURL
	arg3 := "--enrollment-token=" + enrollmentToken
	arg4 := "--certificate-authorities=" + installPath + "soca.crt"
	arg5 := "-n"

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute*3)
	defer cancel()

	exec.CommandContext(ctx, prg, arg1, arg2, arg3, arg4, arg5)

	//strings.join the following
	statusLogs("Executing the following: " + prg + " " + arg1 + " " + arg2 + " " + arg3 + " " + arg4 + " " + arg5)

	output, err := cmd.CombinedOutput()
	check(err, string(output))
	statusLogs(string(output))
	cleanupInstall()

	statusLogs("Elastic Agent installation completed")
	fmt.Println("\n\nInstallation completed successfully.")

}
