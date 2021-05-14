package main

import (
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestAuditConstants(t *testing.T) {
	assert.Equal(t, 7, HEADER_MIN_LENGTH)
	assert.Equal(t, 6, HEADER_START_POS)
	assert.Equal(t, time.Second*2, COMPLETE_AFTER)
	assert.Equal(t, []byte{")"[0]}, headerEndChar)
}

func TestNewAuditMessage(t *testing.T) {
	msg := &syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(44),
			Type:  uint16(1309),
			Flags: uint16(0),
			Seq:   uint32(0),
			Pid:   uint32(0),
		},
		Data: []byte("audit(10000001:99): hi there"),
	}

	am := NewAuditMessage(msg)
	assert.Equal(t, uint16(1309), am.Type)
	assert.Equal(t, 99, am.Seq)
	assert.Equal(t, "10000001", am.AuditTime)
	assert.Equal(t, "hi there", am.Data)
}

func TestAuditMessageGroup_AddMessage(t *testing.T) {
	uidMap = make(map[string]string, 0)
	uidMap["0"] = "hi"
	uidMap["1"] = "nope"

	amg := &AuditMessageGroup{
		Seq:           1,
		AuditTime:     "ok",
		CompleteAfter: time.Now().Add(COMPLETE_AFTER),
	}

	m := &AuditMessage{
		Data: "uid=0 things notuid=nopethisisnot",
	}

	amg.AddMessage(m)
	assert.Equal(t, 1, len(amg.Msgs), "Expected 1 message")
	assert.Equal(t, m, amg.Msgs[0], "First message was wrong")

	// Make sure we don't parse uids for message types that don't have them
	m = &AuditMessage{
		Type: uint16(1309),
		Data: "uid=1",
	}
	amg.AddMessage(m)
	assert.Equal(t, 2, len(amg.Msgs), "Expected 2 messages")
	assert.Equal(t, m, amg.Msgs[1], "2nd message was wrong")

	m = &AuditMessage{
		Type: uint16(1307),
		Data: "uid=1",
	}
	amg.AddMessage(m)
	assert.Equal(t, 3, len(amg.Msgs), "Expected 2 messages")
	assert.Equal(t, m, amg.Msgs[2], "3rd message was wrong")
}

func TestNewAuditMessageGroup(t *testing.T) {
	uidMap = make(map[string]string, 0)
	m := &AuditMessage{
		Type:      uint16(1300),
		Seq:       1019,
		AuditTime: "9919",
		Data:      "Stuff is here",
	}

	amg := NewAuditMessageGroup(m)
	assert.Equal(t, 1019, amg.Seq)
	assert.Equal(t, "9919", amg.AuditTime)
	assert.True(t, amg.CompleteAfter.After(time.Now()), "Complete after time should be greater than right now")
	assert.Equal(t, 6, cap(amg.Msgs), "Msgs capacity should be 6")
	assert.Equal(t, 1, len(amg.Msgs), "Msgs should only have 1 message")
	assert.Equal(t, m, amg.Msgs[0], "First message should be the original")
}
