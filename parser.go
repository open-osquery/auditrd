package auditrd

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

// Creates a new message group from the details parsed from the message
func newAuditMessageGroup(am *AuditMessage) *AuditMessageGroup {
	//TODO: allocating 6 msgs per group is lame and we _should_ know ahead of
	//time roughly how many we need
	amg := &AuditMessageGroup{
		Seq:           am.Seq,
		AuditTime:     am.AuditTime,
		CompleteAfter: time.Now().Add(COMPLETE_AFTER),
		Msgs:          make([]*AuditMessage, 0, 6),
	}

	amg.AddMessage(am)
	return amg
}

// Creates a new auditrd message from a netlink message
func newAuditMessage(nlm *syscall.NetlinkMessage) *AuditMessage {
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
	// If the position the header appears to stop is less than the minimum
	// length of a header, bail out
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
