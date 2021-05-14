package main

import (
	"bytes"
	"strconv"
	"strings"
	"syscall"
	"time"
)

var uidMap = map[string]string{}
var headerEndChar = []byte{")"[0]}
var headerSepChar = byte(':')
var spaceChar = byte(' ')

const (
	HEADER_MIN_LENGTH = 7               // Minimum length of an audit header
	HEADER_START_POS  = 6               // Position in the audit header that the data starts
	COMPLETE_AFTER    = time.Second * 2 // Log a message after this time or EOE
)

type AuditMessage struct {
	Type      uint16 `json:"type"`
	Data      string `json:"data"`
	Seq       int    `json:"-"`
	AuditTime string `json:"-"`

	Containers map[string]string `json:"containers,omitempty"`
}

type AuditMessageGroup struct {
	Seq           int             `json:"sequence"`
	AuditTime     string          `json:"timestamp"`
	CompleteAfter time.Time       `json:"-"`
	Msgs          []*AuditMessage `json:"messages"`
	Syscall       string          `json:"-"`
}

// Creates a new message group from the details parsed from the message
func NewAuditMessageGroup(am *AuditMessage) *AuditMessageGroup {
	//TODO: allocating 6 msgs per group is lame and we _should_ know ahead of time roughly how many we need
	amg := &AuditMessageGroup{
		Seq:           am.Seq,
		AuditTime:     am.AuditTime,
		CompleteAfter: time.Now().Add(COMPLETE_AFTER),
		Msgs:          make([]*AuditMessage, 0, 6),
	}

	amg.AddMessage(am)
	return amg
}

// Creates a new go-audit message from a netlink message
func NewAuditMessage(nlm *syscall.NetlinkMessage) *AuditMessage {
	aTime, seq := parseAuditHeader(nlm)
	return &AuditMessage{
		Type:      nlm.Header.Type,
		Data:      string(nlm.Data),
		Seq:       seq,
		AuditTime: aTime,
	}
}

// Gets the timestamp and audit sequence id from a netlink message
func parseAuditHeader(msg *syscall.NetlinkMessage) (time string, seq int) {
	headerStop := bytes.Index(msg.Data, headerEndChar)
	// If the position the header appears to stop is less than the minimum length of a header, bail out
	if headerStop < HEADER_MIN_LENGTH {
		return
	}

	header := string(msg.Data[:headerStop])
	if header[:HEADER_START_POS] == "audit(" {
		//TODO: out of range check, possibly fully binary?
		sep := strings.IndexByte(header, headerSepChar)
		time = header[HEADER_START_POS:sep]
		seq, _ = strconv.Atoi(header[sep+1:])

		// Remove the header from data
		msg.Data = msg.Data[headerStop+3:]
	}

	return time, seq
}

// Add a new message to the current message group
func (amg *AuditMessageGroup) AddMessage(am *AuditMessage) {
	amg.Msgs = append(amg.Msgs, am)
	//TODO: need to find more message types that won't contain uids, also make these constants
	switch am.Type {
	case 1309, 1307, 1306:
		// Don't map uids here
	case 1300:
		amg.findSyscall(am)
	}
}

func (amg *AuditMessageGroup) findSyscall(am *AuditMessage) {
	data := am.Data
	start := 0
	end := 0

	if start = strings.Index(data, "syscall="); start < 0 {
		return
	}

	// Progress the start point beyond the = sign
	start += 8
	if end = strings.IndexByte(data[start:], spaceChar); end < 0 {
		// There was no ending space, maybe the syscall id is at the end of the line
		end = len(data) - start

		// If the end of the line is greater than 5 characters away (overflows a 16 bit uint) then it can't be a syscall id
		if end > 5 {
			return
		}
	}

	amg.Syscall = data[start : start+end]
}
