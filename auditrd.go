package auditrd

import (
	"time"

	"github.com/golang/glog"
)

//go:generate gomodifytags -file $GOFILE -struct AuditUserEvent -add-tags json -w
type AuditUserEvent struct {
	Msg      string `json:"msg,omitempty"`
	Hostname string `json:"hostname,omitempty"`
	Terminal string `json:"terminal,omitempty"`
	Res      string `json:"res,omitempty"`
}

//go:generate gomodifytags -file $GOFILE -struct AuditSyscallEvent -add-tags json -w
type AuditSyscallEvent struct {
	Syscall string `json:"syscall"`
	Pid     int    `json:"pid"`
	Ppid    int    `json:"ppid"`
	Uid     int    `json:"uid"`
	Auid    int    `json:"auid"`
	Euid    int    `json:"euid"`
	Fsuid   int    `json:"fsuid"`
	Suid    int    `json:"suid"`

	Gid   int `json:"gid"`
	Egid  int `json:"egid"`
	Fsgid int `json:"fsgid"`
	Sgid  int `json:"sgid"`

	Exectuable string `json:"exectuable"`
}

type AuditEvent interface {
	Type() AuditEventType
	Seq() int
	Time() string
}

// AuditMessage represents a single audit message emitted from the netlink
// socket.
type AuditMessage struct {
	Type      uint16 `json:"type"`
	Data      string `json:"data"`
	Seq       int    `json:"-"`
	AuditTime string `json:"-"`

	Containers map[string]string `json:"containers,omitempty"`
}

// AuditMessageTokenMap is a struct that contains a single audit log in key
// value form. The audit log has key values pairs like key=value and a map is
// created out of it.
type AuditMessageTokenMap struct {
	AuditEventType uint16
	Tokens         map[string]string
}

// AuditMessageGroup contains a sequence of audit messages that have the same
// sequence number and it's the sequence number the reply from the socket packet
// counter. Usually the audit message contains a starting packet and ending
// packet and some packets in between. They represent the same event.
type AuditMessageGroup struct {
	Seq           int             `json:"sequence"`
	AuditTime     string          `json:"timestamp"`
	CompleteAfter time.Time       `json:"-"`
	Msgs          []*AuditMessage `json:"messages"`
}

func (amg *AuditMessageGroup) addMessage(am *AuditMessage) {
	amg.Msgs = append(amg.Msgs, am)
}

// NewAuditReader returns a channel which can be read from for the
// AuditMessageGroup which are parsed messages from the netlink socket of the
// NETLINK_AUDIT type.
func NewAuditReader(
	minAuditEventType, maxAuditEventType uint16,
	auditMessageBufferSize int,
	recvSize int,
) (chan *AuditMessageGroup, error) {
	generateSyscallMap()
	out := make(chan *AuditMessageGroup, auditMessageBufferSize)
	marshaller := NewAuditMarshaller(out,
		minAuditEventType, maxAuditEventType, true, false, 5)
	nlClient, err := NewNetlinkClient(recvSize, false)
	if err != nil {
		return nil, err
	}

	go func() {
		for {
			msg, err := nlClient.Receive()
			if err != nil {
				glog.Error("Failed to read message", err)
				continue
			}

			marshaller.Process(msg)
		}
	}()

	return out, nil
}
