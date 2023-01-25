// Copyright Security Onion Solutions LLC and/or licensed to Security Onion Solutions LLC under one
// or more contributor license agreements. Licensed under the Elastic License 2.0; you may not use
// this file except in compliance with the Elastic License 2.0.

// STATUS - WORK IN PROGRESS

package main

import (
	"crypto/tls"
	_ "embed"
	"fmt"
	"github.com/mholt/archiver/v3"
	"github.com/txn2/txeh"
	// "io"
	"flag"
	"net/http"
	"os"
	"os/exec"
	//"path/filepath"
	"strings"
	"time"
)

//go:embed files/cert/intca.crt
var caCRT []byte

var fleetHost = ""
var fleetHostFlag string
var hostFile string

// var installSysmon string
var enrollmentToken, enrollmentTokenFlag string

func check(err error, context string) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", context, err)
		os.Exit(1)
	}
}

func editHosts(fleetIP string, fleetHostname string) {
	hosts, err := txeh.NewHostsDefault()
	if err != nil {
		panic(err)
	}
	hosts.AddHost(fleetIP, fleetHostname)
	hfData := hosts.RenderHostsFile()
	fmt.Println(hfData)
	hosts.Save()
}

func main() {
	// Allow runtime configuration
	flag.StringVar(&enrollmentTokenFlag, "token", "", "Override default Enrollment Token")
	flag.StringVar(&fleetHostFlag, "fleet", "", "Override default Fleet Host")
	flag.StringVar(&hostFile, "hostfile", "", "IP:Hostname - Add Fleet Hostname & IP to local etc/hosts file")
	//flag.StringVar(&showConfig, "config", "", "Show default config")
	flag.Parse()

	if enrollmentTokenFlag != "" {
		enrollmentToken = enrollmentTokenFlag
	}

	if fleetHostFlag != "" {
		fleetHost = fleetHostFlag
	}

	var fleetHostServer = "https://" + fleetHost + ":8220"
	var fleetHostLogstash = "https://" + fleetHost + ":5055"

	// If hostFile != "", add Fleet hostname & IP mapping to local hosts file
	if hostFile != "" {
		s := strings.Split(hostFile, ":")
		fmt.Print(s[0])
		editHosts(s[0], s[1])
	}

	fmt.Printf("\n-== Installation Precheck -==\n\n")

	// Check to make sure that control plane is accessible

	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: 3 * time.Second}

	req, err := http.NewRequest("GET", fleetHostServer, nil)
	resp, err := client.Do(req)

	if err != nil {
		if os.IsTimeout(err) {
			// A timeout error occurred
			check(err, "\n\u00D7 Elastic Fleet is not accessible at: "+fleetHostServer+"\n  - Confirm that Elastic Fleet is up & network access is permitted.\n\nRaw Error Logs:\n")
		}
		// TODO: Add check here for hostname resolution
		// This was an error, but not a timeout
		check(err, "\n\u00D7 Local system cannot resolve Fleet Hostname: "+fleetHostServer+" \n\nRaw Error Logs:\n")
	}

	if resp.StatusCode == http.StatusNotFound {
		fmt.Printf("\n \xE2\x9C\x94 Elastic Fleet (Managment API) is accessible at: " + fleetHostServer + "  -==\n\n")
	} else {
		fmt.Printf("\n \u00D7 Elastic Fleet is not accessible at: " + fleetHostServer + "... Exiting installer. -==\n\n")
		return
	}

	// TODO
	// Check to make sure that data plane is accessible

	//client = &http.Client{Transport: tr, Timeout: 3 * time.Second}
	//req, err = http.NewRequest("GET", fleetHostLogstash, nil)
	//resp, err = client.Do(req)

	//if err != nil {
	//	if os.IsTimeout(err) {
	//		// A timeout error occurred
	//		check(err, "\n\u00D7 Logstash is not accessible at: "+fleetHostLogstash+" \n  - Confirm that Elastic Fleet is up & network access is permitted.\n\nRaw Error Logs:\n")
	//	}
	// TODO: Add check here for hostname resolution
	// This was an error, but not a timeout
	//check(err, "\n\u00D7 Logstash is not accessible at: "+fleetHostLogstash+" \n\nRaw Error Logs:\n")
	//}

	fmt.Printf("\n \xE2\x9C\x94 Elastic Fleet (Data Connection) is accessible at: " + fleetHostLogstash + "  -==\n\n")

	fmt.Printf("\n-== Installation Precheck Complete -==\n\n")

	fmt.Printf("\n-== Extracting Elastic Agent files -==\n\n")

	// Create Elastic Agent install dir & copy SO CA Cert to it
	crtPath := installPath + "soca.crt"

	err = os.MkdirAll(installPath, 0755)
	check(err, "Error creating Elastic Agent directories. \n\nRaw Error Logs:\n")

	err = os.WriteFile(crtPath, caCRT, 0755)
	check(err, "Error copying over the SO ca.crt. \n\nRaw Error Logs:\n")

	// Copy over embedded tar & extract it to the local system
	_ = os.WriteFile("source.tar.gz", agentFiles, 0755)
	archiver.Unarchive("./source.tar.gz", "source")
	check(err, "Error extracting Elastic Agent source. \n\nRaw Error Logs:\n")

	fmt.Printf("\n-== Installing Elastic Agent -==\n\n")

	// Install Elastic Agent
	prg := "./source/elastic-agent/elastic-agent"

	arg1 := "install"
	arg2 := "--url=https://" + fleetHost + ":8220"
	arg3 := "--enrollment-token=" + enrollmentToken
	arg4 := "--certificate-authorities=" + installPath + "soca.crt"
	arg5 := "-n"

	cmd := exec.Command(prg, arg1, arg2, arg3, arg4, arg5)

	fmt.Printf(prg + arg1 + arg2 + arg3 + arg4 + arg5)

	output, err := cmd.CombinedOutput()
	check(err, "Error executing the Elastic Agent installer \n\nRaw Error Logs:\n")
	fmt.Println(string(output))

	os.Remove("./source.tar.gz")
	os.Remove("./source")

	fmt.Printf("\n-== Elastic Agent Installation Completed -==\n\n")

}
