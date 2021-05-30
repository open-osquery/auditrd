package auditrd

import (
	"bytes"
	"strconv"
	"strings"
)

type AuditEventType string

const sep = byte('=')

var (
	Process AuditEventType = "process_event"
	FIM     AuditEventType = "fim_event"
	User    AuditEventType = "user_event"
	Unknown AuditEventType = "unknown"
)

type AuditEventDecoder struct {
}

// The auditContext keeps track of a single audit event id and all the
// information it contains. Once it's parsed, it can be inspected to determine
// what kind of event is it.
type auditContext struct {
	// User IDs in the process context
	uid, gid     int
	euid, egid   int
	suid, sgid   int
	fsuid, fsgid int
	auid         int

	// Fields from the syscall audit record
	executable string
	comm       string
	tty        string
	arch       string
	success    string
	key        string
	syscall    int
	pid        int
	ppid       int
	ses        int
	exit       int

	// Proctitle record
	proctitle string

	// Fields from the audit path record
	cwd       string
	path      string
	dest_path string
	pathItems [5]string

	// User event fields
	msg      string
	hostname string
	terminal string
	res      string

	// Event type which shall be inferred from the events it contains
	eventType string
}

func newAuditContext() *auditContext {
	ctx := new(auditContext)
	ctx.syscall = -1
	return ctx
}

func ProcessEvent2(amg *AuditMessageGroup) {
	for _, msg := range amg.Msgs {
		if msg.Type == AUDIT_SYSCALL {
			//syscall event
		} else if msg.Type >= AUDIT_FIRST_USER_MSG && msg.Type <= AUDIT_LAST_USER_MSG {
			//user event
		}
	}
}

func tokenize(data string) map[string]string {
	m := make(map[string]string)
	escape := false
	token := bytes.Buffer{}

	for i := 0; i < len(data); i++ {
		if escape {
			escape = false
			token.WriteByte(data[i])
			continue
		}

		if data[i] == '\\' {
			escape = true
			continue
		}

		if data[i] == ' ' {
			b := token.Bytes()
			eq := bytes.IndexByte(b, sep)
			if eq != -1 {
				m[string(b[0:eq])] = string(b[eq+1:])
			}
			token.Reset()
			continue
		}
		token.WriteByte(data[i])
	}

	if token.Len() > 0 {
		b := token.Bytes()
		eq := bytes.IndexByte(b, sep)
		if eq != -1 {
			m[string(b[0:eq])] = string(b[eq+1:])
		}
	}
	return m
}

func parseUserAcctEvent(ctx *auditContext, m AuditMessageTokenMap) {
	// pid=16192 uid=1000 auid=1000 ses=1 msg='op=PAM:accounting grantors=pam_permit acct="p0n002h" exe="/usr/bin/sudo" hostname=? addr=? terminal=/dev/pts/2 res=success'
	if m.AuditEventType != AUDIT_USER_ACCT {
		return
	}

	ctx.msg = m.Tokens["msg"]
	ctx.ses, _ = strconv.Atoi(m.Tokens["ses"])
	ctx.pid, _ = strconv.Atoi(m.Tokens["pid"])
	ctx.uid, _ = strconv.Atoi(m.Tokens["uid"])
	ctx.auid, _ = strconv.Atoi(m.Tokens["auid"])
	ctx.executable = strings.Trim(m.Tokens["exe"], `"`)
	ctx.hostname = m.Tokens["hostname"]
	ctx.terminal = m.Tokens["terminal"]
	ctx.res = m.Tokens["res"]
	ctx.key = m.Tokens["key"]
}
