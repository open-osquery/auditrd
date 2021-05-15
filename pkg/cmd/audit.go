package main

import (
	"bytes"
	"flag"
	"io"
	"log"
	"os"

	"github.com/golang/glog"
	"github.com/open-osquery/auditrd/internal/client"
	"github.com/open-osquery/auditrd/internal/marshaller"
)

// A version string that can be set with
//
//     -ldflags "-X main.Build=SOMEVERSION"
//
// at compile-time.
var Build string

func main() {
	flag.Parse()
	marshaller := marshaller.NewAuditMarshaller(1100, 1400, true, false, 5)

	nlClient, err := client.NewNetlinkClient(1024)
	if err != nil {
		log.Fatalln("Failed to create the netlink client")
	}

	for {
		msg, err := nlClient.Receive()
		if err != nil {
			glog.Error("Failed to read message", err)
			continue
		}

		v := marshaller.Process(msg)
		if v != nil {
			v.Msg = append(v.Msg, '\n')
			io.Copy(os.Stdout, bytes.NewBuffer(v.Msg))
		}
	}
}
