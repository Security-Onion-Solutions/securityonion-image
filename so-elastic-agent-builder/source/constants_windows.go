package main

import (
	_ "embed"
)

//go:embed files/elastic-agent/windows.tar.gz
var agentFiles []byte

const installPath = "C:\\Program Files\\Elastic\\SO\\"
