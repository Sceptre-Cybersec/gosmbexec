package main

import (
	"flag"
	"go-smbexec/smbexec"
)

func main() {
	host := flag.String("h", "", "Host name or ip address")
	port := flag.Uint("port", 445, "Port for the SMB service")
	username := flag.String("u", "", "Username")
	domain := flag.String("d", "", "Domain")
	command := flag.String("c", "", "Command")
	commandCOMSPEC := flag.String("comspec", "Y", "CommandCOMSPEC")
	hash := flag.String("hash", "", "Hash")
	password := flag.String("p", "", "Password")
	service := flag.String("service", "", "The name of the service to create, default is random")
	version := flag.String("v", "Auto", "Version: Auto | SMB2.1 | SMB1 (Default: Auto)")

	flag.Parse()

	smbexec.RunDebug(*host, uint16(*port), *username, *password, *hash, *domain, *command, *commandCOMSPEC, *service, *version, true)

}
