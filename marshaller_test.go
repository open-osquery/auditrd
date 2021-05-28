package auditrd

import (
	"syscall"
	"testing"
)

// #define NLMSG_ALIGNTO   4U
const nlmsgAlignTo = 4

// #define NLMSG_ALIGN(len) ( ((len)+NLMSG_ALIGNTO-1) & ~(NLMSG_ALIGNTO-1) )
func nlmsgAlign(len int) int {
	return ((len) + nlmsgAlignTo - 1) & ^(nlmsgAlignTo - 1)
}

func msg1300() *syscall.NetlinkMessage {
	m := &syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(0),
			Type:  AUDIT_SYSCALL,
			Flags: uint16(0),
			Seq:   uint32(1),
			Pid:   uint32(0),
		},
		Data: []byte(`audit(1621634984.633:49129): arch=c000003e syscall=59 success=yes exit=0 a0=5568f3453f40 a1=5568f34456a0 a2=5568f33115f0 a3=8 items=2 ppid=245843 pid=262165 auid=1000 uid=0 gid=0 euid=0 suid=0 fsuid=0 egid=0 sgid=0 fsgid=0 tty=pts3 ses=166 comm="auditctl" exe="/usr/sbin/auditctl" key=(null)`),
	}

	m.Header.Len = uint32(nlmsgAlign(16 + len(m.Data)))
	return m
}

func msg1309() *syscall.NetlinkMessage {
	m := &syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(0),
			Type:  AUDIT_EXECVE,
			Flags: uint16(0),
			Seq:   uint32(1),
			Pid:   uint32(0),
		},
		Data: []byte(`audit(1621634984.633:49129): argc=2 a0="auditctl" a1="-l"`),
	}

	m.Header.Len = uint32(nlmsgAlign(16 + len(m.Data)))
	return m
}

func msg1307() *syscall.NetlinkMessage {
	m := &syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(0),
			Type:  AUDIT_CWD,
			Flags: uint16(0),
			Seq:   uint32(1),
			Pid:   uint32(0),
		},
		Data: []byte(`audit(1621634984.633:49129): cwd="/etc"`),
	}
	m.Header.Len = uint32(nlmsgAlign(16 + len(m.Data)))
	return m
}

func msg1302(count int) []*syscall.NetlinkMessage {
	var msgs = make([]*syscall.NetlinkMessage, 0, count)
	msgs = append(msgs, &syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(0),
			Type:  AUDIT_PATH,
			Flags: uint16(0),
			Seq:   uint32(1),
			Pid:   uint32(0),
		},
		Data: []byte(`audit(1621634984.633:49129): item=0 name="/usr/sbin/auditctl" inode=3036420 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0`),
	})
	msgs[0].Header.Len = uint32(nlmsgAlign(16 + len(msgs[0].Data)))

	if count == 1 {
		return msgs
	}

	msgs = append(msgs, &syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(0),
			Type:  AUDIT_PATH,
			Flags: uint16(0),
			Seq:   uint32(1),
			Pid:   uint32(0),
		},
		Data: []byte(`audit(1621634984.633:49129): item=1 name="/lib64/ld-linux-x86-64.so.2" inode=3020882 dev=fd:00 mode=0100755 ouid=0 ogid=0 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0 cap_frootid=0`),
	})

	msgs[1].Header.Len = uint32(nlmsgAlign(16 + len(msgs[1].Data)))

	if count == 2 {
		return msgs
	}

	return msgs
}

func msg1320() *syscall.NetlinkMessage {
	m := &syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   uint32(0),
			Type:  AUDIT_EOE,
			Flags: uint16(0),
			Seq:   uint32(1),
			Pid:   uint32(0),
		},
		Data: []byte(`audit(1621634984.633:49129): `),
	}
	m.Header.Len = uint32(nlmsgAlign(16 + len(m.Data)))
	return m
}

func TestProcess(t *testing.T) {
	w := make(chan *AuditMessageGroup, 10)
	marshaller := NewAuditMarshaller(w, 1100, 1399, false, false, 0)

	out := make([]*AuditMessageGroup, 0)

	go func() {
		p := msg1302(2)
		marshaller.Process(msg1300())
		marshaller.Process(msg1309())
		marshaller.Process(msg1307())
		marshaller.Process(p[0])
		marshaller.Process(p[1])
		marshaller.Process(msg1320())
		marshaller.completeMessage(49129)
		close(w)
	}()

	for v := range w {
		out = append(out, v)
	}

	if len(out) != 1 {
		t.Errorf("Should have had exactly one audit message group")
		t.FailNow()
	}

	msgGroup := out[0]
	if msgGroup.AuditTime != "1621634984.633" {
		t.FailNow()
	}
}
