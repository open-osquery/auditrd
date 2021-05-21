package auditrd

import (
	"fmt"
	"os"
	"syscall"
	"time"

	"github.com/golang/glog"
)

const (
	EVENT_EOE = 1320 // End of multi packet event
)

type auditMarshaller struct {
	writer            chan *AuditMessageGroup
	msgs              map[int]*AuditMessageGroup
	lastSeq           int
	missed            map[int]bool
	worstLag          int
	minAuditEventType uint16
	maxAuditEventType uint16
	trackMessages     bool
	logOutOfOrder     bool
	maxOutOfOrder     int
	attempts          int
}

// Create a new marshaller
func newAuditMarshaller(
	writer chan *AuditMessageGroup,
	minAuditEventType uint16, maxAuditEventType uint16,
	trackMessages, logOOO bool, maxOOO int,
) *auditMarshaller {
	return &auditMarshaller{
		writer:            writer,
		msgs:              make(map[int]*AuditMessageGroup, 5), // It is not typical to have more than 2 message groups at any given time
		missed:            make(map[int]bool, 10),
		minAuditEventType: minAuditEventType,
		maxAuditEventType: maxAuditEventType,
		trackMessages:     trackMessages,
		logOutOfOrder:     logOOO,
		maxOutOfOrder:     maxOOO,
	}
}

// debug runs only when -v=2 -vlogtostderr=true or higher log settings are
// activated
func debug(aMsg *AuditMessage) {
	if glog.V(2) {
		fmt.Fprintf(
			os.Stderr,
			"(%s:%d:%4d) %s\n",
			aMsg.AuditTime, aMsg.Seq, aMsg.Type, aMsg.Data)
	}
}

// Ingests a netlink message and likely prepares it to be logged
func (a *auditMarshaller) Process(nlMsg *syscall.NetlinkMessage) {
	aMsg := newAuditMessage(nlMsg)

	if aMsg.Seq == 0 {
		// We got an invalid audit message, return the current message and reset
		a.flushOld()
		return
	}

	debug(aMsg)

	if a.trackMessages {
		a.detectMissing(aMsg.Seq)
	}

	if nlMsg.Header.Type < a.minAuditEventType ||
		nlMsg.Header.Type > a.maxAuditEventType {
		// Drop all audit messages that aren't things we care about or end a
		// multi packet event
		a.flushOld()
		return
	} else if nlMsg.Header.Type == EVENT_EOE {
		// This is end of event msg, flush the msg with that sequence and
		// discard this one
		a.completeMessage(aMsg.Seq)
		return
	}

	if val, ok := a.msgs[aMsg.Seq]; ok {
		// Use the original AuditMessageGroup if we have one
		val.AddMessage(aMsg)
	} else {
		// Create a new AuditMessageGroup
		a.msgs[aMsg.Seq] = newAuditMessageGroup(aMsg)
	}

	a.flushOld()
	return
}

// Outputs any messages that are old enough
// This is because there is no indication of multi message events coming from kaudit
func (a *auditMarshaller) flushOld() {
	now := time.Now()
	for seq, msg := range a.msgs {
		if msg.CompleteAfter.Before(now) || now.Equal(msg.CompleteAfter) {
			a.completeMessage(seq)
		}
	}
}

// Write a complete message group to the configured output in json format
func (a *auditMarshaller) completeMessage(seq int) {
	var msg *AuditMessageGroup
	var ok bool

	if msg, ok = a.msgs[seq]; !ok {
		//TODO: attempted to complete a missing message, log?
		glog.Warningf("Message sequence id: %s not found", seq)
		return
	}

	a.writer <- msg
	delete(a.msgs, seq)
}

// Track sequence numbers and log if we suspect we missed a message
func (a *auditMarshaller) detectMissing(seq int) {
	if seq > a.lastSeq+1 && a.lastSeq != 0 {
		// We likely leap frogged over a msg, wait until the next sequence to
		// make sure
		for i := a.lastSeq + 1; i < seq; i++ {
			a.missed[i] = true
		}
	}

	for missedSeq := range a.missed {
		if missedSeq == seq {
			lag := a.lastSeq - missedSeq
			if lag > a.worstLag {
				a.worstLag = lag
			}

			if a.logOutOfOrder {
				glog.V(2).Infoln(
					"Got sequence", missedSeq,
					"after", lag,
					"messages. Worst lag so far", a.worstLag, "messages")
			}
			delete(a.missed, missedSeq)
		} else if seq-missedSeq > a.maxOutOfOrder {
			glog.V(2).Infof(
				"Likely missed sequence %d, current %d, worst message delay %d",
				missedSeq, seq, a.worstLag)
			delete(a.missed, missedSeq)
		}
	}

	if seq > a.lastSeq {
		// Keep track of the largest sequence
		a.lastSeq = seq
	}
}
