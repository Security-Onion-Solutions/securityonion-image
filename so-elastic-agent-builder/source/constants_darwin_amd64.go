package main

import (
	_ "embed"
)

//go:embed files/elastic-agent/darwin-x86_64.tar.gz
var agentFiles []byte

const installPath = "/Library/Elastic/SO/"
