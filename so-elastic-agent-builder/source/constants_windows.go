package main

import (
	_ "embed"
)

//go:embed files/elastic-agent/windows-x86_64.tar.gz
var agentFiles []byte

const installPath = "C:\\Program Files\\Elastic\\SO\\"
