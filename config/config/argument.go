package config

// GetConfigArgument <-- like this
func GetConfigArgument() map[string]string {
	return map[string]string{
		"server":     "-s",
		"serverPort": "-p",
		"protocol":   "-O",
		"method":     "-m",
		"obfs":       "-o",
		"password":   "-k",
		"obfsparam":  "-g",
		"protoparam": "-G",
		"pidFile":    "--pid-file",
		//"logFile":            "--log-file",
		"localAddress": "-b",
		"localPort":    "-l",
		//"connectVerboseInfo": "--connect-verbose-info",
		"workers":  "--workers",
		"fastOpen": "--fast-open",
		"acl":      "--acl",
		"timeout":  "-t",
		"udpTrans": "-u",
	}
}
