package pkg

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"time"

	"github.com/wadeking98/go-smbexec/helpers"

	orderedmap "github.com/wk8/go-ordered-map"
)

// NewPacketSCMOpenSCManagerW creates a new packet for SCMOpenSCManagerW.
func NewPacketSCMOpenSCManagerW(packetService, packetServiceLength []byte) []byte {
	rand.Seed(time.Now().UnixNano())

	packetReferentID1 := make([]byte, 4)
	packetReferentID1[0] = byte(rand.Intn(255) + 1)
	packetReferentID1[1] = byte(rand.Intn(255) + 1)
	packetReferentID1[2] = 0x00
	packetReferentID1[3] = 0x00

	packetReferentID2 := make([]byte, 4)
	packetReferentID2[0] = byte(rand.Intn(255) + 1)
	packetReferentID2[1] = byte(rand.Intn(255) + 1)
	packetReferentID2[2] = 0x00
	packetReferentID2[3] = 0x00

	packetSCMOpenSCManagerW := orderedmap.New()
	packetSCMOpenSCManagerW.Set("MachineName_ReferentID", packetReferentID1)
	packetSCMOpenSCManagerW.Set("MachineName_MaxCount", packetServiceLength)
	packetSCMOpenSCManagerW.Set("MachineName_Offset", []byte{0x00, 0x00, 0x00, 0x00})
	packetSCMOpenSCManagerW.Set("MachineName_ActualCount", packetServiceLength)
	packetSCMOpenSCManagerW.Set("MachineName", packetService)
	packetSCMOpenSCManagerW.Set("Database_ReferentID", packetReferentID2)
	packetSCMOpenSCManagerW.Set("Database_NameMaxCount", []byte{0x0f, 0x00, 0x00, 0x00})
	packetSCMOpenSCManagerW.Set("Database_NameOffset", []byte{0x00, 0x00, 0x00, 0x00})
	packetSCMOpenSCManagerW.Set("Database_NameActualCount", []byte{0x0f, 0x00, 0x00, 0x00})
	packetSCMOpenSCManagerW.Set("Database", []byte{0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00, 0x73, 0x00, 0x41, 0x00, 0x63, 0x00, 0x74, 0x00, 0x69, 0x00, 0x76, 0x00, 0x65, 0x00, 0x00, 0x00})
	packetSCMOpenSCManagerW.Set("Unknown", []byte{0xbf, 0xbf})
	packetSCMOpenSCManagerW.Set("AccessMask", []byte{0x3f, 0x00, 0x00, 0x00})

	return helpers.FlattenOrderedMap(*packetSCMOpenSCManagerW)
}

// NewPacketSCMCreateServiceW creates a new packet for SCMCreateServiceW.
func NewPacketSCMCreateServiceW(contextHandle, service, serviceLength, command, commandLength []byte) []byte {
	rand.Seed(time.Now().UnixNano())

	referentID := make([]byte, 4)
	referentID[0] = byte(rand.Intn(255) + 1)
	referentID[1] = byte(rand.Intn(255) + 1)
	referentID[2] = 0x00
	referentID[3] = 0x00

	packetSCMCreateServiceW := orderedmap.New()
	packetSCMCreateServiceW.Set("ContextHandle", contextHandle)
	packetSCMCreateServiceW.Set("ServiceName_MaxCount", serviceLength)
	packetSCMCreateServiceW.Set("ServiceName_Offset", []byte{0x00, 0x00, 0x00, 0x00})
	packetSCMCreateServiceW.Set("ServiceName_ActualCount", serviceLength)
	packetSCMCreateServiceW.Set("ServiceName", service)
	packetSCMCreateServiceW.Set("DisplayName_ReferentID", referentID)
	packetSCMCreateServiceW.Set("DisplayName_MaxCount", serviceLength)
	packetSCMCreateServiceW.Set("DisplayName_Offset", []byte{0x00, 0x00, 0x00, 0x00})
	packetSCMCreateServiceW.Set("DisplayName_ActualCount", serviceLength)
	packetSCMCreateServiceW.Set("DisplayName", service)
	packetSCMCreateServiceW.Set("AccessMask", []byte{0xff, 0x01, 0x0f, 0x00})
	packetSCMCreateServiceW.Set("ServiceType", []byte{0x10, 0x00, 0x00, 0x00})
	packetSCMCreateServiceW.Set("ServiceStartType", []byte{0x03, 0x00, 0x00, 0x00})
	packetSCMCreateServiceW.Set("ServiceErrorControl", []byte{0x00, 0x00, 0x00, 0x00})
	packetSCMCreateServiceW.Set("BinaryPathName_MaxCount", commandLength)
	packetSCMCreateServiceW.Set("BinaryPathName_Offset", []byte{0x00, 0x00, 0x00, 0x00})
	packetSCMCreateServiceW.Set("BinaryPathName_ActualCount", commandLength)
	packetSCMCreateServiceW.Set("BinaryPathName", command)
	packetSCMCreateServiceW.Set("NULLPointer", []byte{0x00, 0x00, 0x00, 0x00})
	packetSCMCreateServiceW.Set("TagID", []byte{0x00, 0x00, 0x00, 0x00})
	packetSCMCreateServiceW.Set("NULLPointer2", []byte{0x00, 0x00, 0x00, 0x00})
	packetSCMCreateServiceW.Set("DependSize", []byte{0x00, 0x00, 0x00, 0x00})
	packetSCMCreateServiceW.Set("NULLPointer3", []byte{0x00, 0x00, 0x00, 0x00})
	packetSCMCreateServiceW.Set("NULLPointer4", []byte{0x00, 0x00, 0x00, 0x00})
	packetSCMCreateServiceW.Set("PasswordSize", []byte{0x00, 0x00, 0x00, 0x00})

	return helpers.FlattenOrderedMap(*packetSCMCreateServiceW)
}

// NewPacketSCMStartServiceW creates a new packet for SCMStartServiceW.
func NewPacketSCMStartServiceW(contextHandle []byte) []byte {
	packetSCMStartServiceW := orderedmap.New()
	packetSCMStartServiceW.Set("ContextHandle", contextHandle)
	packetSCMStartServiceW.Set("Unknown", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	return helpers.FlattenOrderedMap(*packetSCMStartServiceW)
}

// NewPacketSCMDeleteServiceW creates a new packet for SCMDeleteServiceW.
func NewPacketSCMDeleteServiceW(contextHandle []byte) []byte {
	packetSCMDeleteServiceW := orderedmap.New()
	packetSCMDeleteServiceW.Set("ContextHandle", contextHandle)

	return helpers.FlattenOrderedMap(*packetSCMDeleteServiceW)
}

// NewPacketSCMCloseServiceHandle creates a new packet for SCMCloseServiceHandle.
func NewPacketSCMCloseServiceHandle(contextHandle []byte) []byte {
	packetSCMCloseServiceHandle := orderedmap.New()
	packetSCMCloseServiceHandle.Set("ContextHandle", contextHandle)

	return helpers.FlattenOrderedMap(*packetSCMCloseServiceHandle)
}

// GetStatusPending checks if the status is pending.
func GetStatusPending(status []byte) bool {
	statusString := fmt.Sprintf("%X-%X-%X-%X", status[0], status[1], status[2], status[3])
	return statusString == "03-01-00-00"
}

// GetUInt16DataLength retrieves the uint16 data length from the given start position in the data slice.
func GetUInt16DataLength(start int, data []byte) uint16 {
	return binary.LittleEndian.Uint16(data[start : start+2])
}
