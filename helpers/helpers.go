package helpers

import (
	"encoding/binary"
	"fmt"
	"os"
	"strconv"

	orderedmap "github.com/wk8/go-ordered-map"
)

type Logger struct {
	Print bool
}

func (l *Logger) Println(out interface{}) {
	if l.Print {
		fmt.Println(out)
	}
}

func (l *Logger) Printf(out string, vars ...interface{}) {
	if l.Print {
		fmt.Printf(out, vars...)
	}
}

func FlattenMap(data map[string][]byte) []byte {
	var flattened []byte
	for _, value := range data {
		flattened = append(flattened, value...)
	}
	return flattened
}

func FlattenOrderedMap(data orderedmap.OrderedMap) []byte {
	valueArray := []byte{}
	current := data.Oldest()
	for current != nil {
		valueArray = append(valueArray, current.Value.([]byte)...)
		current = current.Next()
	}
	return valueArray
}

func GetCurrentProcessID() int {
	return os.Getpid()
}

func GetUInt16DataLength(start int, data []byte) uint16 {
	dataLength := binary.LittleEndian.Uint16(data[start : start+2])
	return dataLength
}

func ParseHex(hex string) byte {
	value, _ := strconv.ParseInt(hex, 16, 0)
	return byte(value)
}

func Uint16ToBytes(inp []uint16) []byte {
	buf := []byte{}
	for _, item := range inp {
		buf = binary.LittleEndian.AppendUint16(buf, item)
	}
	return buf
}

func FromUint16Bytes(inp []byte) []byte {
	buf := []byte{}
	for i, item := range inp {
		if i%2 == 0 {
			buf = append(buf, item)
		}
	}
	return buf
}

func ReverseArray[K interface{}](numbers []K) []K {
	for i := 0; i < len(numbers)/2; i++ {
		j := len(numbers) - i - 1
		numbers[i], numbers[j] = numbers[j], numbers[i]
	}
	return numbers
}
