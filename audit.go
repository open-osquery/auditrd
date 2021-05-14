package main

import (
	"log"
	"os"

	"github.com/golang/glog"
)

// A version string that can be set with
//
//     -ldflags "-X main.Build=SOMEVERSION"
//
// at compile-time.
var Build string

func main() {
	writer := NewAuditWriter(os.Stdout, 1)
	marshaller := NewAuditMarshaller(
		writer, 0, 10000, true, false, 5)

	nlClient, err := NewNetlinkClient(1024)
	if err != nil {
		log.Fatalln("Failed to create the netlink client")
	}

	for {
		msg, err := nlClient.Receive()
		if err != nil {
			glog.Error("Failed to read message", err)
			continue
		}

		marshaller.Consume(msg)
	}
}
