package auditrd

import (
	"bytes"
)

const sep = byte('=')

func Tokenize(data string) map[string]string {
	m := make(map[string]string)
	escape := false
	token := bytes.Buffer{}

	for i := 0; i < len(data); i++ {
		if escape {
			escape = false
			token.WriteByte(data[i])
			continue
		}

		if data[i] == '\\' {
			escape = true
			continue
		}

		if data[i] == ' ' {
			b := token.Bytes()
			eq := bytes.IndexByte(b, sep)
			if eq != -1 {
				m[string(b[0:eq])] = string(b[eq+1:])
			}
			token.Reset()
			continue
		}
		token.WriteByte(data[i])
	}

	if token.Len() > 0 {
		b := token.Bytes()
		eq := bytes.IndexByte(b, sep)
		if eq != -1 {
			m[string(b[0:eq])] = string(b[eq+1:])
		}
	}
	return m
}
