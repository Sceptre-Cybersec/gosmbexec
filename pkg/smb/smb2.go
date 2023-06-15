package smb

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"go-smbexec/helpers"

	orderedmap "github.com/wk8/go-ordered-map"
)

func ComputeSigniture2(packetSMB2Header *orderedmap.OrderedMap, sessionKey []byte, smbSignList ...[]byte) []byte {
	SMB2Sign := []byte{}
	for _, item := range smbSignList {
		SMB2Sign = append(SMB2Sign, item...)
	}
	sha := hmac.New(sha256.New, sessionKey)
	sha.Write(SMB2Sign)
	SMB2Signature := sha.Sum(nil)[:16]
	packetSMB2Header.Set("Signature", SMB2Signature)
	return helpers.FlattenOrderedMap(*packetSMB2Header)
}

func NewPacketSMB2HeaderUnflat(Command []byte, CreditRequest []byte, Signing bool, MessageID int, ProcessID []byte, TreeID []byte, SessionID []byte) *orderedmap.OrderedMap {
	var flags []byte

	if Signing {
		flags = []byte{0x08, 0x00, 0x00, 0x00}
	} else {
		flags = []byte{0x00, 0x00, 0x00, 0x00}
	}

	messageID := make([]byte, 8)
	binary.LittleEndian.PutUint16(messageID, uint16(MessageID))

	SMB2Header := orderedmap.New()
	SMB2Header.Set("ProtocolID", []byte{0xfe, 0x53, 0x4d, 0x42})
	SMB2Header.Set("StructureSize", []byte{0x40, 0x00})
	SMB2Header.Set("CreditCharge", []byte{0x01, 0x00})
	SMB2Header.Set("ChannelSequence", []byte{0x00, 0x00})
	SMB2Header.Set("Reserved", []byte{0x00, 0x00})
	SMB2Header.Set("Command", Command)
	SMB2Header.Set("CreditRequest", CreditRequest)
	SMB2Header.Set("Flags", flags)
	SMB2Header.Set("NextCommand", []byte{0x00, 0x00, 0x00, 0x00})
	SMB2Header.Set("MessageID", messageID)
	SMB2Header.Set("ProcessID", ProcessID)
	SMB2Header.Set("TreeID", TreeID)
	SMB2Header.Set("SessionID", SessionID)
	SMB2Header.Set("Signature", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	return SMB2Header
}

func NewPacketSMB2Header(Command []byte, CreditRequest []byte, Signing bool, MessageID int, ProcessID []byte, TreeID []byte, SessionID []byte) []byte {
	SMB2Header := NewPacketSMB2HeaderUnflat(Command, CreditRequest, Signing, MessageID, ProcessID, TreeID, SessionID)

	return helpers.FlattenOrderedMap(*SMB2Header)
}

func NewPacketSMB2NegotiateProtocolRequest() []byte {
	SMB2NegotiateProtocolRequest := orderedmap.New()
	SMB2NegotiateProtocolRequest.Set("StructureSize", []byte{0x24, 0x00})
	SMB2NegotiateProtocolRequest.Set("DialectCount", []byte{0x02, 0x00})
	SMB2NegotiateProtocolRequest.Set("SecurityMode", []byte{0x01, 0x00})
	SMB2NegotiateProtocolRequest.Set("Reserved", []byte{0x00, 0x00})
	SMB2NegotiateProtocolRequest.Set("Capabilities", []byte{0x40, 0x00, 0x00, 0x00})
	SMB2NegotiateProtocolRequest.Set("ClientGUID", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	SMB2NegotiateProtocolRequest.Set("NegotiateContextOffset", []byte{0x00, 0x00, 0x00, 0x00})
	SMB2NegotiateProtocolRequest.Set("NegotiateContextCount", []byte{0x00, 0x00})
	SMB2NegotiateProtocolRequest.Set("Reserved2", []byte{0x00, 0x00})
	SMB2NegotiateProtocolRequest.Set("Dialect", []byte{0x02, 0x02})
	SMB2NegotiateProtocolRequest.Set("Dialect2", []byte{0x10, 0x02})

	return helpers.FlattenOrderedMap(*SMB2NegotiateProtocolRequest)
}

func NewPacketSMB2SessionSetupRequest(SecurityBlob []byte) []byte {
	securityBufferLength := make([]byte, 2)
	binary.LittleEndian.PutUint16(securityBufferLength, uint16(len(SecurityBlob)))

	SMB2SessionSetupRequest := orderedmap.New()
	SMB2SessionSetupRequest.Set("StructureSize", []byte{0x19, 0x00})
	SMB2SessionSetupRequest.Set("Flags", []byte{0x00})
	SMB2SessionSetupRequest.Set("SecurityMode", []byte{0x01})
	SMB2SessionSetupRequest.Set("Capabilities", []byte{0x00, 0x00, 0x00, 0x00})
	SMB2SessionSetupRequest.Set("Channel", []byte{0x00, 0x00, 0x00, 0x00})
	SMB2SessionSetupRequest.Set("SecurityBufferOffset", []byte{0x58, 0x00})
	SMB2SessionSetupRequest.Set("SecurityBufferLength", securityBufferLength)
	SMB2SessionSetupRequest.Set("PreviousSessionID", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	SMB2SessionSetupRequest.Set("Buffer", SecurityBlob)

	return helpers.FlattenOrderedMap(*SMB2SessionSetupRequest)
}

func NewPacketSMB2TreeConnectRequest(Buffer []byte) []byte {
	pathLength := make([]byte, 2)
	binary.LittleEndian.PutUint16(pathLength, uint16(len(Buffer)))

	SMB2TreeConnectRequest := orderedmap.New()
	SMB2TreeConnectRequest.Set("StructureSize", []byte{0x09, 0x00})
	SMB2TreeConnectRequest.Set("Reserved", []byte{0x00, 0x00})
	SMB2TreeConnectRequest.Set("PathOffset", []byte{0x48, 0x00})
	SMB2TreeConnectRequest.Set("PathLength", pathLength)
	SMB2TreeConnectRequest.Set("Buffer", Buffer)

	return helpers.FlattenOrderedMap(*SMB2TreeConnectRequest)
}

func NewPacketSMB2CreateRequestFileUnflat(NamedPipe []byte) *orderedmap.OrderedMap {
	nameLength := make([]byte, 2)
	binary.LittleEndian.PutUint16(nameLength, uint16(len(NamedPipe)))

	SMB2CreateRequestFile := orderedmap.New()
	SMB2CreateRequestFile.Set("StructureSize", []byte{0x39, 0x00})
	SMB2CreateRequestFile.Set("Flags", []byte{0x00})
	SMB2CreateRequestFile.Set("RequestedOplockLevel", []byte{0x00})
	SMB2CreateRequestFile.Set("Impersonation", []byte{0x02, 0x00, 0x00, 0x00})
	SMB2CreateRequestFile.Set("SMBCreateFlags", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	SMB2CreateRequestFile.Set("Reserved", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	SMB2CreateRequestFile.Set("DesiredAccess", []byte{0x03, 0x00, 0x00, 0x00})
	SMB2CreateRequestFile.Set("FileAttributes", []byte{0x80, 0x00, 0x00, 0x00})
	SMB2CreateRequestFile.Set("ShareAccess", []byte{0x01, 0x00, 0x00, 0x00})
	SMB2CreateRequestFile.Set("CreateDisposition", []byte{0x01, 0x00, 0x00, 0x00})
	SMB2CreateRequestFile.Set("CreateOptions", []byte{0x40, 0x00, 0x00, 0x00})
	SMB2CreateRequestFile.Set("NameOffset", []byte{0x78, 0x00})
	SMB2CreateRequestFile.Set("NameLength", nameLength)
	SMB2CreateRequestFile.Set("CreateContextsOffset", []byte{0x00, 0x00, 0x00, 0x00})
	SMB2CreateRequestFile.Set("CreateContextsLength", []byte{0x00, 0x00, 0x00, 0x00})
	SMB2CreateRequestFile.Set("Buffer", NamedPipe)

	return SMB2CreateRequestFile
}

func NewPacketSMB2CreateRequestFile(NamedPipe []byte) []byte {

	return helpers.FlattenOrderedMap(*NewPacketSMB2CreateRequestFileUnflat(NamedPipe))
}

func NewPacketSMB2ReadRequestUnflat(FileID []byte) *orderedmap.OrderedMap {
	SMB2ReadRequest := orderedmap.New()
	SMB2ReadRequest.Set("StructureSize", []byte{0x31, 0x00})
	SMB2ReadRequest.Set("Padding", []byte{0x50})
	SMB2ReadRequest.Set("Flags", []byte{0x00})
	SMB2ReadRequest.Set("Length", []byte{0x00, 0x00, 0x10, 0x00})
	SMB2ReadRequest.Set("Offset", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	SMB2ReadRequest.Set("FileID", FileID)
	SMB2ReadRequest.Set("MinimumCount", []byte{0x00, 0x00, 0x00, 0x00})
	SMB2ReadRequest.Set("Channel", []byte{0x00, 0x00, 0x00, 0x00})
	SMB2ReadRequest.Set("RemainingBytes", []byte{0x00, 0x00, 0x00, 0x00})
	SMB2ReadRequest.Set("ReadChannelInfoOffset", []byte{0x00, 0x00})
	SMB2ReadRequest.Set("ReadChannelInfoLength", []byte{0x00, 0x00})
	SMB2ReadRequest.Set("Buffer", []byte{0x30})

	return SMB2ReadRequest
}

func NewPacketSMB2ReadRequest(FileID []byte) []byte {

	return helpers.FlattenOrderedMap(*NewPacketSMB2ReadRequestUnflat(FileID))
}

func NewPacketSMB2WriteRequest(FileID []byte, RPCLength int) []byte {
	writeLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(writeLength, uint32(RPCLength))

	SMB2WriteRequest := orderedmap.New()
	SMB2WriteRequest.Set("StructureSize", []byte{0x31, 0x00})
	SMB2WriteRequest.Set("DataOffset", []byte{0x70, 0x00})
	SMB2WriteRequest.Set("Length", writeLength)
	SMB2WriteRequest.Set("Offset", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	SMB2WriteRequest.Set("FileID", FileID)
	SMB2WriteRequest.Set("Channel", []byte{0x00, 0x00, 0x00, 0x00})
	SMB2WriteRequest.Set("RemainingBytes", []byte{0x00, 0x00, 0x00, 0x00})
	SMB2WriteRequest.Set("WriteChannelInfoOffset", []byte{0x00, 0x00})
	SMB2WriteRequest.Set("WriteChannelInfoLength", []byte{0x00, 0x00})
	SMB2WriteRequest.Set("Flags", []byte{0x00, 0x00, 0x00, 0x00})

	return helpers.FlattenOrderedMap(*SMB2WriteRequest)
}

func NewPacketSMB2CloseRequest(FileID []byte) []byte {
	SMB2CloseRequest := orderedmap.New()
	SMB2CloseRequest.Set("StructureSize", []byte{0x18, 0x00})
	SMB2CloseRequest.Set("Flags", []byte{0x00, 0x00})
	SMB2CloseRequest.Set("Reserved", []byte{0x00, 0x00, 0x00, 0x00})
	SMB2CloseRequest.Set("FileID", FileID)

	return helpers.FlattenOrderedMap(*SMB2CloseRequest)
}

func NewPacketSMB2TreeDisconnectRequest() []byte {
	SMB2TreeDisconnectRequest := orderedmap.New()
	SMB2TreeDisconnectRequest.Set("StructureSize", []byte{0x04, 0x00})
	SMB2TreeDisconnectRequest.Set("Reserved", []byte{0x00, 0x00})

	return helpers.FlattenOrderedMap(*SMB2TreeDisconnectRequest)
}

func NewPacketSMB2SessionLogoffRequest() []byte {
	SMB2SessionLogoffRequest := orderedmap.New()
	SMB2SessionLogoffRequest.Set("StructureSize", []byte{0x04, 0x00})
	SMB2SessionLogoffRequest.Set("Reserved", []byte{0x00, 0x00})

	return helpers.FlattenOrderedMap(*SMB2SessionLogoffRequest)
}
