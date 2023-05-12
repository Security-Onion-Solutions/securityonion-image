package main

import (
	_ "embed"
)

//go:embed files/elastic-agent/darwin-aarch64.tar.gz
var agentFiles []byte

const installPath = "/Library/Elastic/SO/"
