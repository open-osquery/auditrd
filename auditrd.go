package auditrd

import (
	"time"

	"github.com/golang/glog"
)

//go:generate easytags $GOFILE
type AuditEvent struct {
	Arch        string `json:"arch"`
	Success     string `json:"success"`
	Syscall     int    `json:"syscall"`
	Exit        int    `json:"exit"`
	Ppid        int    `json:"ppid"`
	Pid         int    `json:"pid"`
	Auid        int    `json:"auid"`
	Uid         int    `json:"uid"`
	Gid         int    `json:"gid"`
	Euid        int    `json:"euid"`
	Suid        int    `json:"suid"`
	Fsuid       int    `json:"fsuid"`
	Egid        int    `json:"egid"`
	Sgid        int    `json:"sgid"`
	Fsgid       int    `json:"fsgid"`
	Session     int    `json:"session"`
	Tty         string `json:"tty"`
	Comm        string `json:"comm"`
	Key         string `json:"key"`
	Cwd         string `json:"cwd"`
	Exectuable  string `json:"exectuable"`
	Commandline string `json:"commandline"`
	Path        string `json:"path,omitempty"`
	DestPath    string `json:"dest_path,omitempty"`
}

type AuditMessage struct {
	Type      uint16 `json:"type"`
	Data      string `json:"data"`
	Seq       int    `json:"-"`
	AuditTime string `json:"-"`

	Containers map[string]string `json:"containers,omitempty"`
}

type AuditMessageTokenMap struct {
	AuditEventType uint16            `json:"audit_event_type"`
	Tokens         map[string]string `json:"tokens"`
}

type AuditMessageGroup struct {
	Seq           int             `json:"sequence"`
	AuditTime     string          `json:"timestamp"`
	CompleteAfter time.Time       `json:"-"`
	Msgs          []*AuditMessage `json:"messages"`
}

func (amg *AuditMessageGroup) AddMessage(am *AuditMessage) {
	amg.Msgs = append(amg.Msgs, am)
}

func NewAuditReader(
	minAuditEventType, maxAuditEventType uint16,
	auditMessageBufferSize int,
	recvSize int,
) (chan *AuditMessageGroup, error) {
	out := make(chan *AuditMessageGroup, auditMessageBufferSize)
	marshaller := NewAuditMarshaller(out,
		minAuditEventType, maxAuditEventType, true, false, 5)
	nlClient, err := NewNetlinkClient(recvSize)
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
