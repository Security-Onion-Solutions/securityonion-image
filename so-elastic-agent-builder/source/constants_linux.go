package main

import (
	_ "embed"
)

//go:embed files/elastic-agent/linux-x86_64.tar.gz
var agentFiles []byte

const installPath = "/opt/Elastic/SO/"
