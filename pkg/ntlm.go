package pkg

import (
	"encoding/binary"

	"github.com/wadeking98/go-smbexec/helpers"

	orderedmap "github.com/wk8/go-ordered-map"
)

func NewPacketNTLMSSPNegotiate(negotiateFlags []byte, version []byte) []byte {
	ntlmsspLength := make([]byte, 4)
	binary.LittleEndian.PutUint32(ntlmsspLength, uint32(len(version)+32))
	ntlmsspLength = ntlmsspLength[:1]
	asnLength1 := []byte{ntlmsspLength[0] + 32}
	asnLength2 := []byte{ntlmsspLength[0] + 22}
	asnLength3 := []byte{ntlmsspLength[0] + 20}
	asnLength4 := []byte{ntlmsspLength[0] + 2}

	ntlmsspNegotiate := orderedmap.New()
	ntlmsspNegotiate.Set("InitialContextTokenID", []byte{0x60})
	ntlmsspNegotiate.Set("InitialcontextTokenLength", asnLength1)
	ntlmsspNegotiate.Set("ThisMechID", []byte{0x06})
	ntlmsspNegotiate.Set("ThisMechLength", []byte{0x06})
	ntlmsspNegotiate.Set("OID", []byte{0x2b, 0x06, 0x01, 0x05, 0x05, 0x02})
	ntlmsspNegotiate.Set("InnerContextTokenID", []byte{0xa0})
	ntlmsspNegotiate.Set("InnerContextTokenLength", asnLength2)
	ntlmsspNegotiate.Set("InnerContextTokenID2", []byte{0x30})
	ntlmsspNegotiate.Set("InnerContextTokenLength2", asnLength3)
	ntlmsspNegotiate.Set("MechTypesID", []byte{0xa0})
	ntlmsspNegotiate.Set("MechTypesLength", []byte{0x0e})
	ntlmsspNegotiate.Set("MechTypesID2", []byte{0x30})
	ntlmsspNegotiate.Set("MechTypesLength2", []byte{0x0c})
	ntlmsspNegotiate.Set("MechTypesID3", []byte{0x06})
	ntlmsspNegotiate.Set("MechTypesLength3", []byte{0x0a})
	ntlmsspNegotiate.Set("MechType", []byte{0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a})
	ntlmsspNegotiate.Set("MechTokenID", []byte{0xa2})
	ntlmsspNegotiate.Set("MechTokenLength", asnLength4)
	ntlmsspNegotiate.Set("NTLMSSPID", []byte{0x04})
	ntlmsspNegotiate.Set("NTLMSSPLength", ntlmsspLength)
	ntlmsspNegotiate.Set("Identifier", []byte{0x4e, 0x54, 0x4c, 0x4d, 0x53, 0x53, 0x50, 0x00})
	ntlmsspNegotiate.Set("MessageType", []byte{0x01, 0x00, 0x00, 0x00})
	ntlmsspNegotiate.Set("NegotiateFlags", negotiateFlags)
	ntlmsspNegotiate.Set("CallingWorkstationDomain", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	ntlmsspNegotiate.Set("CallingWorkstationName", []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})

	if len(version) > 0 {
		ntlmsspNegotiate.Set("Version", version)
	}

	return helpers.FlattenOrderedMap(*ntlmsspNegotiate)
}

func NewPacketNTLMSSPAuth(ntlmResponse []byte) []byte {
	ntlmsspLength := make([]byte, 2)
	binary.BigEndian.PutUint16(ntlmsspLength, uint16(len(ntlmResponse)))
	asnLength1 := make([]byte, 2)
	binary.BigEndian.PutUint16(asnLength1, uint16(len(ntlmResponse)+12))
	asnLength2 := make([]byte, 2)
	binary.BigEndian.PutUint16(asnLength2, uint16(len(ntlmResponse)+8))
	asnLength3 := make([]byte, 2)
	binary.BigEndian.PutUint16(asnLength3, uint16(len(ntlmResponse)+4))

	ntlmsspAuth := orderedmap.New()
	ntlmsspAuth.Set("ASNID", []byte{0xa1, 0x82})
	ntlmsspAuth.Set("ASNLength", asnLength1)
	ntlmsspAuth.Set("ASNID2", []byte{0x30, 0x82})
	ntlmsspAuth.Set("ASNLength2", asnLength2)
	ntlmsspAuth.Set("ASNID3", []byte{0xa2, 0x82})
	ntlmsspAuth.Set("ASNLength3", asnLength3)
	ntlmsspAuth.Set("NTLMSSPID", []byte{0x04, 0x82})
	ntlmsspAuth.Set("NTLMSSPLength", ntlmsspLength)
	ntlmsspAuth.Set("NTLMResponse", ntlmResponse)

	return helpers.FlattenOrderedMap(*ntlmsspAuth)
}
