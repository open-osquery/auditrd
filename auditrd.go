package auditrd

import (
	"time"

	"github.com/golang/glog"
)

//go:generate gomodifytags -file $GOFILE -struct AuditEvent -add-tags json -w
type AuditEvent struct {
	Name        string `json:"name"`
	Arch        string `json:"arch,omitempty"`
	Success     string `json:"success,omitempty"`
	Syscall     string `json:"syscall"`
	Exit        int    `json:"exit"`
	Ppid        int    `json:"ppid"`
	Pid         int    `json:"pid"`
	Auid        int    `json:"auid"`
	Uid         int    `json:"uid"`
	Gid         int    `json:"gid"`
	Euid        int    `json:"euid"`
	Egid        int    `json:"egid"`
	Fsuid       int    `json:"fsuid"`
	Fsgid       int    `json:"fsgid"`
	Suid        int    `json:"suid"`
	Sgid        int    `json:"sgid"`
	Session     int    `json:"session"`
	Tty         string `json:"tty,omitempty"`
	Comm        string `json:"comm,omitempty"`
	Key         string `json:"key,omitempty"`
	Cwd         string `json:"cwd,omitempty"`
	Exectuable  string `json:"exectuable,omitempty"`
	Commandline string `json:"commandline,omitempty"`
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
	AuditEventType uint16
	Tokens         map[string]string
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
	generateSyscallMap()
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
