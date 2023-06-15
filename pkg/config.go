package pkg

import (
	"encoding/hex"

	"golang.org/x/crypto/md4"
)

type SmbConfig struct {
	SmbVersion   *string
	Target       *string
	Username     *string
	Domain       *string
	Command      *string
	CommandSpec  *string
	Hash         *string
	SmbExecute   bool
	Service      *string
	SigningCheck bool
	Session      *bool
	Logoff       *bool
	Refresh      *bool
	Sleep        *int
	Debug        *bool
}

func calcNTLM(in string) string {
	/* Prepare a byte array to return */
	var u16 []byte

	/* Add all bytes, as well as the 0x00 of UTF-16 */
	for _, b := range []byte(in) {
		u16 = append(u16, b)
		u16 = append(u16, 0x00)
	}

	/* Hash the byte array with MD4 */
	mdfour := md4.New()
	mdfour.Write(u16)

	/* Return the output */
	return hex.EncodeToString(mdfour.Sum(nil))
}

func NewSmbConfig(SmbVersion *string, Target *string, Username *string, Domain *string, Command *string, CommandSpec *string, Password *string, Hash *string, Service *string, Session *bool, Logoff *bool, Refresh *bool, Sleep *int, Debug *bool) SmbConfig {
	SigningCheck := false
	if *Username == "" && *Password == "" && *Hash == "" && !*Session {
		SigningCheck = true
	}

	if *Password != "" {
		*Hash = calcNTLM(*Password)
	}

	SmbExecute := *Command != ""
	return SmbConfig{
		SmbVersion,
		Target,
		Username,
		Domain,
		Command,
		CommandSpec,
		Hash,
		SmbExecute,
		Service,
		SigningCheck,
		Session,
		Logoff,
		Refresh,
		Sleep,
		Debug,
	}
}
