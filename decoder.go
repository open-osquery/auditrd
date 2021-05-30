package auditrd

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"strconv"
	"strings"
)

type AuditEventType string

var (
	ProcessEvent AuditEventType = "process_event"
	FIMEvent     AuditEventType = "fim_event"
	UserEvent    AuditEventType = "user_event"
)

// eventParsers is a map that holds functions that contains parser for different
// audit message types which take in a parsed audit message token map and
// populates the Audit context passed to it.
var eventParsers = map[uint16]func(*auditContext, AuditMessageTokenMap){
	1101: parseUserAcctEvent,
	1300: parseSyscallEvent,
	1302: parsePathEvent,
	1307: parseCwdEvent,
	1327: parseProctitleEvent,
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

// ParseAuditEvent is a audit message parser that reads all the events for an
// audit event id and returns 2 types of AuditEvents, "process_event" and
// "fim_event" depending on what syscalls they were emitted for. If the list of
// audit events don't qualify for either of them, a nil event and false is
// returned which must be checked to identify a failed parsing.
func ParseAuditEvent(tokenList []AuditMessageTokenMap) (*AuditEvent, bool) {
	ctx := newAuditContext()

	// Potentially a UserEvent. Need to find a better way to classify an event
	// group.
	if len(tokenList) == 1 {
		v := tokenList[0]
		if v.AuditEventType == 1305 {
			return nil, false
		}

		if parser, ok := eventParsers[v.AuditEventType]; ok {
			parser(ctx, v)
		}

		if IsUserEvent(v.AuditEventType) {
			return parseUserEvent(ctx)
		}

		return nil, false
	}

	for _, v := range tokenList {
		if parser, ok := eventParsers[v.AuditEventType]; ok {
			parser(ctx, v)
		}
	}

	if IsExecSyscall(ctx.syscall) {
		return parseProcessEvent(ctx)
	}
	if IsFIMSyscall(ctx.syscall) {
		return parseFIMEvent(ctx)
	}

	return nil, false
}

// Create a process Event from an audit context once it's detected as a process
// event.
func parseProcessEvent(auditCtx *auditContext) (*AuditEvent, bool) {
	ae := &AuditEvent{
		Arch:        auditCtx.arch,
		Syscall:     SyscallName(auditCtx.syscall),
		Success:     auditCtx.success,
		Exit:        auditCtx.exit,
		Ppid:        auditCtx.ppid,
		Pid:         auditCtx.pid,
		Auid:        auditCtx.auid,
		Uid:         auditCtx.uid,
		Gid:         auditCtx.gid,
		Euid:        auditCtx.euid,
		Suid:        auditCtx.suid,
		Fsuid:       auditCtx.fsuid,
		Egid:        auditCtx.egid,
		Sgid:        auditCtx.sgid,
		Fsgid:       auditCtx.fsgid,
		Tty:         auditCtx.tty,
		Session:     auditCtx.ses,
		Comm:        auditCtx.comm,
		Exectuable:  auditCtx.executable,
		Commandline: auditCtx.proctitle,
		Cwd:         auditCtx.cwd,
		Key:         auditCtx.key,
		Name:        ProcessEvent,
	}

	return ae, true
}

// Creates a FIM Event from an audit context once it's detected as a FIM event.
func parseFIMEvent(auditCtx *auditContext) (*AuditEvent, bool) {
	// Since this a FIM event, there must be filepaths involved other than the
	// regular 2 AUDIT_PATH record. It's necessary to get those paths resolved
	// to their absolute paths for processing.
	resolvePath(auditCtx)

	ae := &AuditEvent{
		Arch:        auditCtx.arch,
		Syscall:     SyscallName(auditCtx.syscall),
		Success:     auditCtx.success,
		Exit:        auditCtx.exit,
		Ppid:        auditCtx.ppid,
		Pid:         auditCtx.pid,
		Auid:        auditCtx.auid,
		Uid:         auditCtx.uid,
		Gid:         auditCtx.gid,
		Euid:        auditCtx.euid,
		Suid:        auditCtx.suid,
		Fsuid:       auditCtx.fsuid,
		Egid:        auditCtx.egid,
		Sgid:        auditCtx.sgid,
		Fsgid:       auditCtx.fsgid,
		Tty:         auditCtx.tty,
		Session:     auditCtx.ses,
		Comm:        auditCtx.comm,
		Exectuable:  auditCtx.executable,
		Commandline: auditCtx.proctitle,
		Cwd:         auditCtx.cwd,
		Key:         auditCtx.key,
		Name:        FIMEvent,
	}

	// Additional steps in case the syscall is of the rename family
	ae.Path = auditCtx.path
	ae.DestPath = auditCtx.dest_path

	return ae, true
}

func parseUserEvent(auditCtx *auditContext) (*AuditEvent, bool) {
	return &AuditEvent{
		Success:    auditCtx.res,
		Msg:        auditCtx.msg,
		Pid:        auditCtx.pid,
		Auid:       auditCtx.auid,
		Uid:        auditCtx.uid,
		Session:    auditCtx.ses,
		Exectuable: auditCtx.executable,
		Key:        auditCtx.key,
		Name:       UserEvent,
	}, true
}

func resolvePath(ctx *auditContext) {
	l := 0
	for i := 0; i < 5; i++ {
		ctx.pathItems[i] = strings.Trim(ctx.pathItems[i], `"`)
		if len(ctx.pathItems[i]) > 0 {
			l++
		}
	}

	switch l {
	case 2:
		if filepath.IsAbs(ctx.pathItems[1]) {
			ctx.path = ctx.pathItems[1]
		} else {
			ctx.path = filepath.Join(ctx.cwd, filepath.Clean(ctx.pathItems[1]))
		}

	case 4:
		// In case of rename/renameat/renameat2 the items represent the
		// following values
		//
		// item 0: working directory of the first path
		// item 1: working directory of the second path
		// item 2: source file name
		// item 3: destination file name
		ctx.path = normalizePath(ctx.cwd, ctx.pathItems[0], ctx.pathItems[2])
		ctx.dest_path = normalizePath(ctx.cwd, ctx.pathItems[1], ctx.pathItems[3])

	case 5:
		// If the destination file is being overwritten:
		//
		// item 0: working directory of the first path
		// item 1: working directory of the second path
		// item 2: source file name
		// item 3: file being overwritten
		// item 4: destination file name
		//
		// In this case the items 3 and 4 have the same path but
		// different inodes
		ctx.path = normalizePath(ctx.cwd, ctx.pathItems[0], ctx.pathItems[2])
		ctx.dest_path = normalizePath(ctx.cwd, ctx.pathItems[1], ctx.pathItems[4])
	}
}

func normalizePath(cwd, path_cwd, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}

	if !filepath.IsAbs(path_cwd) {
		path_cwd = filepath.Join(cwd, filepath.Clean(path_cwd))
	}

	rp, err := filepath.Rel(path_cwd, path)
	if err != nil {
		return filepath.Join(cwd, path)
	}

	return filepath.Join(path_cwd, rp)
}

func parseSyscallEvent(ctx *auditContext, m AuditMessageTokenMap) {
	if m.AuditEventType != 1300 {
		return
	}

	ctx.arch = m.Tokens["arch"]
	ctx.syscall, _ = strconv.Atoi(m.Tokens["syscall"])
	ctx.success = m.Tokens["success"]
	ctx.exit, _ = strconv.Atoi(m.Tokens["exit"])
	ctx.ppid, _ = strconv.Atoi(m.Tokens["ppid"])
	ctx.pid, _ = strconv.Atoi(m.Tokens["pid"])

	ctx.auid, _ = strconv.Atoi(m.Tokens["auid"])
	ctx.uid, _ = strconv.Atoi(m.Tokens["uid"])
	ctx.gid, _ = strconv.Atoi(m.Tokens["gid"])
	ctx.euid, _ = strconv.Atoi(m.Tokens["euid"])
	ctx.egid, _ = strconv.Atoi(m.Tokens["egid"])
	ctx.fsuid, _ = strconv.Atoi(m.Tokens["fsuid"])
	ctx.fsgid, _ = strconv.Atoi(m.Tokens["fsgid"])
	ctx.suid, _ = strconv.Atoi(m.Tokens["suid"])
	ctx.sgid, _ = strconv.Atoi(m.Tokens["sgid"])

	ctx.ses, _ = strconv.Atoi(m.Tokens["ses"])

	ctx.tty = m.Tokens["tty"]
	ctx.comm = strings.Trim(m.Tokens["comm"], `"`)
	ctx.executable = strings.Trim(m.Tokens["exe"], `"`)

	ctx.key = strings.Trim(m.Tokens["key"], `"`)
}

func parseCwdEvent(ctx *auditContext, m AuditMessageTokenMap) {
	if m.AuditEventType != 1307 {
		return
	}

	ctx.cwd = strings.Trim(m.Tokens["cwd"], `"`)
}

func parsePathEvent(ctx *auditContext, m AuditMessageTokenMap) {
	if m.AuditEventType != 1302 {
		return
	}

	item, _ := strconv.Atoi(m.Tokens["item"])
	ctx.pathItems[item] = m.Tokens["name"]
}

func parseProctitleEvent(ctx *auditContext, m AuditMessageTokenMap) {
	if m.AuditEventType != 1327 {
		return
	}

	var p string = m.Tokens["proctitle"]
	if strings.HasPrefix(p, `"`) {
		ctx.proctitle = strings.Trim(p, `"`)
		return
	}

	args, _ := hex.DecodeString(p)
	ctx.proctitle = string(bytes.ReplaceAll(args, []byte{0}, []byte{' '}))
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
