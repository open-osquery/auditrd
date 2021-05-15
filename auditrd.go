package auditrd

import (
	"github.com/golang/glog"
	"github.com/open-osquery/auditrd/internal/client"
	"github.com/open-osquery/auditrd/internal/marshaller"
	"github.com/open-osquery/auditrd/pkg/message"
)

func NewAuditReader(
	minAuditEventType, maxAuditEventType uint16,
	auditMessageBufferSize int,
	recvSize int,
) (chan *message.AuditMessage, error) {
	marshaller := marshaller.NewAuditMarshaller(
		minAuditEventType, maxAuditEventType, true, false, 5)
	nlClient, err := client.NewNetlinkClient(recvSize)
	if err != nil {
		return nil, err
	}

	out := make(chan *message.AuditMessage, auditMessageBufferSize)
	for {
		msg, err := nlClient.Receive()
		if err != nil {
			glog.Error("Failed to read message", err)
			continue
		}

		auditMessage := marshaller.Process(msg)
		out <- auditMessage
	}
}
