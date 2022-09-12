package main

import (
	_ "embed"
)

//go:embed files/elastic-agent/linux.tar.gz
var agentFiles []byte

const installPath = "/opt/Elastic/SO/"
