package main

import (
	"encoding/json"
	"flag"
	"os"

	"github.com/open-osquery/auditrd"
)

// A version string that can be set with
//
//     -ldflags "-X main.Build=SOMEVERSION"
//
// at compile-time.
var Build string

func main() {
	flag.Parse()
	rd, _ := auditrd.NewAuditReader(1100, 1400, 1024, 1024)
	for msg := range rd {
		if msg != nil {
			tokenList := make([]auditrd.AuditMessageTokenMap, 0, 6)
			for _, d := range msg.Msgs {
				tokenList = append(tokenList, auditrd.AuditMessageTokenMap{
					AuditEventType: d.Type,
					Tokens:         auditrd.Tokenize(d.Data),
				})
			}

			ev, ok := auditrd.ParseAuditEvent(tokenList)
			if ok {
				json.NewEncoder(os.Stdout).Encode(ev)
			}
		}
	}
}
