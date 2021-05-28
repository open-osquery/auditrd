package auditrd

import (
	"syscall"
	"testing"
	"time"
)

func TestAuditConstants(t *testing.T) {
	if 7 != HEADER_MIN_LENGTH {
		t.FailNow()
	}

	if 6 != HEADER_START_POS {
		t.FailNow()
	}

	if time.Second*2 != COMPLETE_AFTER {
		t.FailNow()
	}

	if byte(')') != headerSepChar {
		t.FailNow()
	}
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

	am := newAuditMessage(msg)
	if uint16(1309) != am.Type {
		t.FailNow()
	}

	if 99 != am.Seq {
		t.FailNow()
	}

	if "10000001" != am.AuditTime {
		t.FailNow()
	}

	if "hi there" != am.Data {
		t.FailNow()
	}
}

func TestAuditMessageGroup_addMessage(t *testing.T) {
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

	amg.addMessage(m)
	if 1 != len(amg.Msgs) {
		t.Error("Expected 1 messge")
		t.FailNow()
	}

	if m != amg.Msgs[0] {
		t.Error("First message was wrong")
		t.FailNow()
	}

	// Make sure we don't parse uids for message types that don't have them
	m = &AuditMessage{
		Type: uint16(1309),
		Data: "uid=1",
	}
	amg.addMessage(m)
	if 2 != len(amg.Msgs) {
		t.Error("Expected 2 messges")
		t.FailNow()
	}

	if m != amg.Msgs[1] {
		t.Error("Second message was wrong")
		t.FailNow()
	}

	m = &AuditMessage{
		Type: uint16(1307),
		Data: "uid=1",
	}
	amg.addMessage(m)
	if 3 != len(amg.Msgs) {
		t.Error("Expected 3 messges")
		t.FailNow()
	}

	if m != amg.Msgs[2] {
		t.Error("3rd message was wrong")
		t.FailNow()
	}
}

func TestNewAuditMessageGroup(t *testing.T) {
	uidMap = make(map[string]string, 0)
	m := &AuditMessage{
		Type:      uint16(1300),
		Seq:       1019,
		AuditTime: "9919",
		Data:      "Stuff is here",
	}

	amg := newAuditMessageGroup(m)
	if 1019 != amg.Seq {
		t.FailNow()
	}

	if "9919" != amg.AuditTime {
		t.FailNow()
	}

	if !amg.CompleteAfter.After(time.Now()) {
		t.Error("Complete after time should be greater than right now")
		t.FailNow()
	}

	if cap(amg.Msgs) != 6 {
		t.Error("Msgs capacity should be 6")
		t.FailNow()
	}

	if 1 != len(amg.Msgs) {
		t.Error("Msgs should only have 1 message")
		t.FailNow()
	}

	if m != amg.Msgs[0] {
		t.Error("First message should be the original")
		t.FailNow()
	}
}
