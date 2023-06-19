package smb

import (
	"crypto/md5"
	"encoding/binary"

	"github.com/wadeking98/go-smbexec/helpers"

	orderedmap "github.com/wk8/go-ordered-map"
)

func SetSmbSignitureAndFlags(packetSMBHeader *orderedmap.OrderedMap, SMBSigningCounter *int) {
	packetSMBHeader.Set("Flags2", []byte{0x05, 0x48})
	*SMBSigningCounter += 2
	SMBSigningSequence := make([]byte, 4)
	binary.LittleEndian.PutUint32(SMBSigningSequence, uint32(*SMBSigningCounter))
	SMBSigningSequence = append(SMBSigningSequence, []byte{0x00, 0x00, 0x00, 0x00}...)
	packetSMBHeader.Set("Signature", SMBSigningSequence)
}

func ComputeSigniture(packetSMBHeader *orderedmap.OrderedMap, smbSignList ...[]byte) []byte {
	SMBSign := []byte{}
	for _, item := range smbSignList {
		SMBSign = append(SMBSign, item...)
	}
	md5 := md5.New()
	md5.Write(SMBSign)
	SMBSignature := md5.Sum(nil)[:8]
	packetSMBHeader.Set("Signature", SMBSignature)
	return helpers.FlattenOrderedMap(*packetSMBHeader)
}

func NewPacketSMBHeaderUnflat(command, flags, flags2, treeID, processID, userID []byte) *orderedmap.OrderedMap {

	smbHeader := orderedmap.New()
	smbHeader.Set("Protocol", []byte{0xff, 0x53, 0x4d, 0x42})
	smbHeader.Set("Command", command)
	smbHeader.Set("ErrorClass", []byte{0x00})
	smbHeader.Set("Reserved", []byte{0x00})
	smbHeader.Set("ErrorCode", []byte{0x00, 0x00})
	smbHeader.Set("Flags", flags)
	smbHeader.Set("Flags2", flags2)
	smbHeader.Set("ProcessIDHigh", []byte{0x00, 0x00})
	smbHeader.Set("Signature", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	smbHeader.Set("Reserved2", []byte{0x00, 0x00})
	smbHeader.Set("TreeID", treeID)
	smbHeader.Set("ProcessID", processID)
	smbHeader.Set("UserID", userID)
	smbHeader.Set("MultiplexID", []byte{0x00, 0x00})
	return smbHeader
}

func NewPacketSMBHeader(command, flags, flags2, treeID, processID, userID []byte) []byte {
	return helpers.FlattenOrderedMap(*NewPacketSMBHeaderUnflat(command, flags, flags2, treeID, processID, userID))
}

func NewPacketSMBNegotiateProtocolRequest(version string) []byte {
	var byteCount []byte

	if version == "SMB1" {
		byteCount = []byte{0x0c, 0x00}
	} else {
		byteCount = []byte{0x22, 0x00}
	}

	smbNegotiateProtocolRequest := orderedmap.New()
	smbNegotiateProtocolRequest.Set("WordCount", []byte{0x00})
	smbNegotiateProtocolRequest.Set("ByteCount", byteCount)
	smbNegotiateProtocolRequest.Set("RequestedDialects_Dialect_BufferFormat", []byte{0x02})
	smbNegotiateProtocolRequest.Set("RequestedDialects_Dialect_Name", []byte{0x4e, 0x54, 0x20, 0x4c, 0x4d, 0x20, 0x30, 0x2e, 0x31, 0x32, 0x00})

	if version != "SMB1" {
		smbNegotiateProtocolRequest.Set("RequestedDialects_Dialect_BufferFormat2", []byte{0x02})
		smbNegotiateProtocolRequest.Set("RequestedDialects_Dialect_Name2", []byte{0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x30, 0x30, 0x32, 0x00})
		smbNegotiateProtocolRequest.Set("RequestedDialects_Dialect_BufferFormat3", []byte{0x02})
		smbNegotiateProtocolRequest.Set("RequestedDialects_Dialect_Name3", []byte{0x53, 0x4d, 0x42, 0x20, 0x32, 0x2e, 0x3f, 0x3f, 0x3f, 0x00})
	}

	return helpers.FlattenOrderedMap(*smbNegotiateProtocolRequest)
}

func NewPacketSMBSessionSetupAndXRequest(securityBlob []byte) []byte {
	byteCount := make([]byte, 2)
	securityBlobLength := make([]byte, 2)

	binary.LittleEndian.PutUint16(byteCount, uint16(len(securityBlob)))
	binary.LittleEndian.PutUint16(securityBlobLength, uint16(len(securityBlob)+5))

	smbSessionSetupAndXRequest := orderedmap.New()
	smbSessionSetupAndXRequest.Set("WordCount", []byte{0x0c})
	smbSessionSetupAndXRequest.Set("AndXCommand", []byte{0xff})
	smbSessionSetupAndXRequest.Set("Reserved", []byte{0x00})
	smbSessionSetupAndXRequest.Set("AndXOffset", []byte{0x00, 0x00})
	smbSessionSetupAndXRequest.Set("MaxBuffer", []byte{0xff, 0xff})
	smbSessionSetupAndXRequest.Set("MaxMpxCount", []byte{0x02, 0x00})
	smbSessionSetupAndXRequest.Set("VCNumber", []byte{0x01, 0x00})
	smbSessionSetupAndXRequest.Set("SessionKey", []byte{0x00, 0x00, 0x00, 0x00})
	smbSessionSetupAndXRequest.Set("SecurityBlobLength", byteCount)
	smbSessionSetupAndXRequest.Set("Reserved2", []byte{0x00, 0x00, 0x00, 0x00})
	smbSessionSetupAndXRequest.Set("Capabilities", []byte{0x44, 0x00, 0x00, 0x80})
	smbSessionSetupAndXRequest.Set("ByteCount", securityBlobLength)
	smbSessionSetupAndXRequest.Set("SecurityBlob", securityBlob)
	smbSessionSetupAndXRequest.Set("NativeOS", []byte{0x00, 0x00, 0x00})
	smbSessionSetupAndXRequest.Set("NativeLANManage", []byte{0x00, 0x00})

	return helpers.FlattenOrderedMap(*smbSessionSetupAndXRequest)
}

func NewPacketSMBTreeConnectAndXRequest(path []byte) []byte {
	pathLength := make([]byte, 2)
	binary.LittleEndian.PutUint16(pathLength, uint16(len(path)+7))

	smbTreeConnectAndXRequest := orderedmap.New()
	smbTreeConnectAndXRequest.Set("WordCount", []byte{0x04})
	smbTreeConnectAndXRequest.Set("AndXCommand", []byte{0xff})
	smbTreeConnectAndXRequest.Set("Reserved", []byte{0x00})
	smbTreeConnectAndXRequest.Set("AndXOffset", []byte{0x00, 0x00})
	smbTreeConnectAndXRequest.Set("Flags", []byte{0x00, 0x00})
	smbTreeConnectAndXRequest.Set("PasswordLength", []byte{0x01, 0x00})
	smbTreeConnectAndXRequest.Set("ByteCount", pathLength)
	smbTreeConnectAndXRequest.Set("Password", []byte{0x00})
	smbTreeConnectAndXRequest.Set("Tree", path)
	smbTreeConnectAndXRequest.Set("Service", []byte{0x3f, 0x3f, 0x3f, 0x3f, 0x3f, 0x00})

	return helpers.FlattenOrderedMap(*smbTreeConnectAndXRequest)
}

func NewPacketSMBNTCreateAndXRequest(namedPipe []byte) []byte {
	namedPipeLength := make([]byte, 2)
	binary.LittleEndian.PutUint16(namedPipeLength, uint16(len(namedPipe)))

	fileNameLength := make([]byte, 2)
	binary.LittleEndian.PutUint16(fileNameLength, uint16(len(namedPipe)-1))

	smbNTCreateAndXRequest := orderedmap.New()
	smbNTCreateAndXRequest.Set("WordCount", []byte{0x18})
	smbNTCreateAndXRequest.Set("AndXCommand", []byte{0xff})
	smbNTCreateAndXRequest.Set("Reserved", []byte{0x00})
	smbNTCreateAndXRequest.Set("AndXOffset", []byte{0x00, 0x00})
	smbNTCreateAndXRequest.Set("Reserved2", []byte{0x00})
	smbNTCreateAndXRequest.Set("FileNameLen", fileNameLength)
	smbNTCreateAndXRequest.Set("CreateFlags", []byte{0x16, 0x00, 0x00, 0x00})
	smbNTCreateAndXRequest.Set("RootFID", []byte{0x00, 0x00, 0x00, 0x00})
	smbNTCreateAndXRequest.Set("AccessMask", []byte{0x00, 0x00, 0x00, 0x02})
	smbNTCreateAndXRequest.Set("AllocationSize", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	smbNTCreateAndXRequest.Set("FileAttributes", []byte{0x00, 0x00, 0x00, 0x00})
	smbNTCreateAndXRequest.Set("ShareAccess", []byte{0x07, 0x00, 0x00, 0x00})
	smbNTCreateAndXRequest.Set("Disposition", []byte{0x01, 0x00, 0x00, 0x00})
	smbNTCreateAndXRequest.Set("CreateOptions", []byte{0x00, 0x00, 0x00, 0x00})
	smbNTCreateAndXRequest.Set("Impersonation", []byte{0x02, 0x00, 0x00, 0x00})
	smbNTCreateAndXRequest.Set("SecurityFlags", []byte{0x00})
	smbNTCreateAndXRequest.Set("ByteCount", namedPipeLength)
	smbNTCreateAndXRequest.Set("Filename", namedPipe)

	return helpers.FlattenOrderedMap(*smbNTCreateAndXRequest)
}

func NewPacketSMBReadAndXRequest(fid []byte) []byte {
	smbReadAndXRequest := orderedmap.New()
	smbReadAndXRequest.Set("WordCount", []byte{0x0a})
	smbReadAndXRequest.Set("AndXCommand", []byte{0xff})
	smbReadAndXRequest.Set("Reserved", []byte{0x00})
	smbReadAndXRequest.Set("AndXOffset", []byte{0x00, 0x00})
	smbReadAndXRequest.Set("FID", fid)
	smbReadAndXRequest.Set("Offset", []byte{0x00, 0x00, 0x00, 0x00})
	smbReadAndXRequest.Set("MaxCountLow", []byte{0x58, 0x02})
	smbReadAndXRequest.Set("MinCount", []byte{0x58, 0x02})
	smbReadAndXRequest.Set("Unknown", []byte{0xff, 0xff, 0xff, 0xff})
	smbReadAndXRequest.Set("Remaining", []byte{0x00, 0x00})
	smbReadAndXRequest.Set("ByteCount", []byte{0x00, 0x00})

	return helpers.FlattenOrderedMap(*smbReadAndXRequest)
}

func NewPacketSMBWriteAndXRequest(fileID []byte, length int) []byte {
	writeLength := make([]byte, 2)
	writeLength[0] = byte(length & 0xff)
	writeLength[1] = byte((length >> 8) & 0xff)

	smbWriteAndXRequest := orderedmap.New()
	smbWriteAndXRequest.Set("WordCount", []byte{0x0e})
	smbWriteAndXRequest.Set("AndXCommand", []byte{0xff})
	smbWriteAndXRequest.Set("Reserved", []byte{0x00})
	smbWriteAndXRequest.Set("AndXOffset", []byte{0x00, 0x00})
	smbWriteAndXRequest.Set("FID", fileID)
	smbWriteAndXRequest.Set("Offset", []byte{0xea, 0x03, 0x00, 0x00})
	smbWriteAndXRequest.Set("Reserved2", []byte{0xff, 0xff, 0xff, 0xff})
	smbWriteAndXRequest.Set("WriteMode", []byte{0x08, 0x00})
	smbWriteAndXRequest.Set("Remaining", writeLength)
	smbWriteAndXRequest.Set("DataLengthHigh", []byte{0x00, 0x00})
	smbWriteAndXRequest.Set("DataLengthLow", writeLength)
	smbWriteAndXRequest.Set("DataOffset", []byte{0x3f, 0x00})
	smbWriteAndXRequest.Set("HighOffset", []byte{0x00, 0x00, 0x00, 0x00})
	smbWriteAndXRequest.Set("ByteCount", writeLength)

	return helpers.FlattenOrderedMap(*smbWriteAndXRequest)
}

func NewPacketSMBCloseRequest(fileID []byte) []byte {
	smbCloseRequest := orderedmap.New()
	smbCloseRequest.Set("WordCount", []byte{0x03})
	smbCloseRequest.Set("FID", fileID)
	smbCloseRequest.Set("LastWrite", []byte{0xff, 0xff, 0xff, 0xff})
	smbCloseRequest.Set("ByteCount", []byte{0x00, 0x00})

	return helpers.FlattenOrderedMap(*smbCloseRequest)
}

func NewPacketSMBTreeDisconnectRequest() []byte {
	smbTreeDisconnectRequest := orderedmap.New()
	smbTreeDisconnectRequest.Set("WordCount", []byte{0x00})
	smbTreeDisconnectRequest.Set("ByteCount", []byte{0x00, 0x00})

	return helpers.FlattenOrderedMap(*smbTreeDisconnectRequest)
}

func NewPacketSMBLogoffAndXRequest() []byte {
	smbLogoffAndXRequest := orderedmap.New()
	smbLogoffAndXRequest.Set("WordCount", []byte{0x02})
	smbLogoffAndXRequest.Set("AndXCommand", []byte{0xff})
	smbLogoffAndXRequest.Set("Reserved", []byte{0x00})
	smbLogoffAndXRequest.Set("AndXOffset", []byte{0x00, 0x00})
	smbLogoffAndXRequest.Set("ByteCount", []byte{0x00, 0x00})

	return helpers.FlattenOrderedMap(*smbLogoffAndXRequest)
}
