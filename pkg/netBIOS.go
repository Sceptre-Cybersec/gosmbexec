package pkg

import (
	"encoding/binary"
	"go-smbexec/helpers"

	orderedmap "github.com/wk8/go-ordered-map"
)

func NewPacketNetBIOSSessionService(headerLength, dataLength int) []byte {
	length := make([]byte, 4)
	binary.LittleEndian.PutUint32(length, uint32(headerLength+dataLength))

	netBIOSSessionService := orderedmap.New()
	netBIOSSessionService.Set("MessageType", []byte{0x00})
	netBIOSSessionService.Set("Length", helpers.ReverseArray(length)[1:4])

	return helpers.FlattenOrderedMap(*netBIOSSessionService)
}
