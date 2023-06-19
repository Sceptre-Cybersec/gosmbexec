package pkg

import (
	"encoding/binary"

	"github.com/wadeking98/gosmbexec/helpers"

	orderedmap "github.com/wk8/go-ordered-map"
)

func NewPacketRPCBind(fragLength []byte, callID int, numCtxItems []byte, contextID []byte, uuid []byte, uuidVersion []byte) []byte {
	callIDBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(callIDBytes, uint32(callID))

	rpcBind := orderedmap.New()
	rpcBind.Set("Version", []byte{0x05})
	rpcBind.Set("VersionMinor", []byte{0x00})
	rpcBind.Set("PacketType", []byte{0x0b})
	rpcBind.Set("PacketFlags", []byte{0x03})
	rpcBind.Set("DataRepresentation", []byte{0x10, 0x00, 0x00, 0x00})
	rpcBind.Set("FragLength", fragLength)
	rpcBind.Set("AuthLength", []byte{0x00, 0x00})
	rpcBind.Set("CallID", callIDBytes)
	rpcBind.Set("MaxXmitFrag", []byte{0xb8, 0x10})
	rpcBind.Set("MaxRecvFrag", []byte{0xb8, 0x10})
	rpcBind.Set("AssocGroup", []byte{0x00, 0x00, 0x00, 0x00})
	rpcBind.Set("NumCtxItems", numCtxItems)
	rpcBind.Set("Unknown", []byte{0x00, 0x00, 0x00})
	rpcBind.Set("ContextID", contextID)
	rpcBind.Set("NumTransItems", []byte{0x01})
	rpcBind.Set("Unknown2", []byte{0x00})
	rpcBind.Set("Interface", uuid)
	rpcBind.Set("InterfaceVer", uuidVersion)
	rpcBind.Set("InterfaceVerMinor", []byte{0x00, 0x00})
	rpcBind.Set("TransferSyntax", []byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60})
	rpcBind.Set("TransferSyntaxVer", []byte{0x02, 0x00, 0x00, 0x00})

	if numCtxItems[0] == 2 {
		rpcBind.Set("ContextID2", []byte{0x01, 0x00})
		rpcBind.Set("NumTransItems2", []byte{0x01})
		rpcBind.Set("Unknown3", []byte{0x00})
		rpcBind.Set("Interface2", uuid)
		rpcBind.Set("InterfaceVer2", uuidVersion)
		rpcBind.Set("InterfaceVerMinor2", []byte{0x00, 0x00})
		rpcBind.Set("TransferSyntax2", []byte{0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		rpcBind.Set("TransferSyntaxVer2", []byte{0x01, 0x00, 0x00, 0x00})
	} else if numCtxItems[0] == 3 {
		rpcBind.Set("ContextID2", []byte{0x01, 0x00})
		rpcBind.Set("NumTransItems2", []byte{0x01})
		rpcBind.Set("Unknown3", []byte{0x00})
		rpcBind.Set("Interface2", uuid)
		rpcBind.Set("InterfaceVer2", uuidVersion)
		rpcBind.Set("InterfaceVerMinor2", []byte{0x00, 0x00})
		rpcBind.Set("TransferSyntax2", []byte{0x33, 0x05, 0x71, 0x71, 0xba, 0xbe, 0x37, 0x49, 0x83, 0x19, 0xb5, 0xdb, 0xef, 0x9c, 0xcc, 0x36})
		rpcBind.Set("TransferSyntaxVer2", []byte{0x01, 0x00, 0x00, 0x00})
		rpcBind.Set("ContextID3", []byte{0x02, 0x00})
		rpcBind.Set("NumTransItems3", []byte{0x01})
		rpcBind.Set("Unknown4", []byte{0x00})
		rpcBind.Set("Interface3", uuid)
		rpcBind.Set("InterfaceVer3", uuidVersion)
		rpcBind.Set("InterfaceVerMinor3", []byte{0x00, 0x00})
		rpcBind.Set("TransferSyntax3", []byte{0x2c, 0x1c, 0xb7, 0x6c, 0x12, 0x98, 0x40, 0x45, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		rpcBind.Set("TransferSyntaxVer3", []byte{0x01, 0x00, 0x00, 0x00})
	}

	if callID == 3 {
		rpcBind.Set("AuthType", []byte{0x0a})
		rpcBind.Set("AuthLevel", []byte{0x02})
		rpcBind.Set("AuthPadLength", []byte{0x00})
		rpcBind.Set("AuthReserved", []byte{0x00})
		rpcBind.Set("ContextID3", []byte{0x00, 0x00, 0x00, 0x00})
		rpcBind.Set("Identifier", []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00})
		rpcBind.Set("MessageType", []byte{0x01, 0x00, 0x00, 0x00})
		rpcBind.Set("NegotiateFlags", []byte{0x97, 0x82, 0x08, 0xe2})
		rpcBind.Set("CallingWorkstationDomain", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		rpcBind.Set("CallingWorkstationName", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		rpcBind.Set("OSVersion", []byte{0x06, 0x01, 0xb1, 0x1d, 0x00, 0x00, 0x00, 0x0f})
	}

	return helpers.FlattenOrderedMap(*rpcBind)
}

func NewPacketRPCRequest(flags []byte, serviceLength int, authLength int, authPadding int, callID []byte, contextID []byte, opnum []byte, data []byte) []byte {

	return helpers.FlattenOrderedMap(*NewPacketRPCRequestUnflat(flags, serviceLength, authLength, authPadding, callID, contextID, opnum, data))
}

func NewPacketRPCRequestUnflat(flags []byte, serviceLength int, authLength int, authPadding int, callID []byte, contextID []byte, opnum []byte, data []byte) *orderedmap.OrderedMap {
	var fullAuthLength int
	if authLength > 0 {
		fullAuthLength = authLength + authPadding + 8
	}

	writeLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(writeLength, uint32(serviceLength+24+fullAuthLength+len(data)))
	fragLength := writeLength[:2]
	allocHint := make([]byte, 4)
	binary.LittleEndian.PutUint32(allocHint, uint32(serviceLength+len(data)))
	authLengthBytes := make([]byte, 2)
	binary.LittleEndian.PutUint16(authLengthBytes, uint16(authLength))

	rpcRequest := orderedmap.New()
	rpcRequest.Set("Version", []byte{0x05})
	rpcRequest.Set("VersionMinor", []byte{0x00})
	rpcRequest.Set("PacketType", []byte{0x00})
	rpcRequest.Set("PacketFlags", flags)
	rpcRequest.Set("DataRepresentation", []byte{0x10, 0x00, 0x00, 0x00})
	rpcRequest.Set("FragLength", fragLength)
	rpcRequest.Set("AuthLength", authLengthBytes)
	rpcRequest.Set("CallID", callID)
	rpcRequest.Set("AllocHint", allocHint)
	rpcRequest.Set("ContextID", contextID)
	rpcRequest.Set("Opnum", opnum)

	if len(data) > 0 {
		rpcRequest.Set("Data", data)
	}

	return rpcRequest
}
