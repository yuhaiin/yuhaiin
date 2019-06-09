package config

func argumentMatch(argument map[string]string, configTemp2 []string) {
	switch configTemp2[0] {
	case "python_path":
		argument["pythonPath"] = configTemp2[1]
	case "-python_path":
		argument["pythonPath"] = ""
	case "ssr_path":
		argument["ssrPath"] = configTemp2[1]
	case "-ssr_path":
		argument["ssrPath"] = ""
	case "config_path":
		argument["configPath"] = configTemp2[1]
	case "connect-verbose-info":
		argument["connectVerboseInfo"] = "--connect-verbose-info"
	case "workers":
		argument["workers"] = configTemp2[1]
	case "fast-open":
		argument["fastOpen"] = "fast-open"
	case "pid-file":
		argument["pidFile"] = configTemp2[1]
	case "-pid-file":
		argument["pidFile"] = ""
	case "log-file":
		argument["logFile"] = configTemp2[1]
	case "-log-file":
		argument["logFile"] = ""
	case "local_address":
		argument["localAddress"] = configTemp2[1]
	case "local_port":
		argument["localPort"] = configTemp2[1]
	case "acl":
		argument["acl"] = configTemp2[1]
	case "timeout":
		argument["timeout"] = configTemp2[1]
		// case "daemon":
		// 	argument["daemon"] = "-d start"
	}
}
