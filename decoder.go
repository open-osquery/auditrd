package auditrd

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"strconv"
	"strings"
)

type auditFIMContext struct {
	uid, gid     int
	euid, egid   int
	suid, sgid   int
	fsuid, fsgid int
	auid         int

	executable string
	pid, ppid  int
	comm       string
	ses        int
	tty        string
	arch       string
	syscall    int
	exit       int
	success    string
	key        string

	proctitle string
	cwd       string
	path      string
	dest_path string

	pathItems [5]string
}

func ParseFIMEvent(tokenList []AuditMessageTokenMap) *AuditEvent {
	ctx := new(auditFIMContext)
	for _, v := range tokenList {
		switch v.AuditEventType {
		case 1300:
			parseSyscallEvent(ctx, v)
		case 1302:
			parsePathEvent(ctx, v)
		case 1307:
			parseCwdEvent(ctx, v)
		case 1327:
			parseProctitleEvent(ctx, v)
		}
	}

	ae := &AuditEvent{
		Arch:        ctx.arch,
		Syscall:     ctx.syscall,
		Success:     ctx.success,
		Exit:        ctx.exit,
		Ppid:        ctx.ppid,
		Pid:         ctx.pid,
		Auid:        ctx.auid,
		Uid:         ctx.uid,
		Gid:         ctx.gid,
		Euid:        ctx.euid,
		Suid:        ctx.suid,
		Fsuid:       ctx.fsuid,
		Egid:        ctx.egid,
		Sgid:        ctx.sgid,
		Fsgid:       ctx.fsgid,
		Tty:         ctx.tty,
		Session:     ctx.ses,
		Comm:        ctx.comm,
		Exectuable:  ctx.executable,
		Commandline: ctx.proctitle,
		Cwd:         ctx.cwd,
		Key:         ctx.key,
	}

	resolvePath(ctx)

	ae.Path = ctx.path
	ae.DestPath = ctx.dest_path

	return ae
}

func resolvePath(ctx *auditFIMContext) {
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

func parseSyscallEvent(
	ctx *auditFIMContext, m AuditMessageTokenMap,
) {
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

func parseCwdEvent(ctx *auditFIMContext, m AuditMessageTokenMap) {
	if m.AuditEventType != 1307 {
		return
	}

	ctx.cwd = strings.Trim(m.Tokens["cwd"], `"`)
}

func parsePathEvent(ctx *auditFIMContext, m AuditMessageTokenMap) {
	if m.AuditEventType != 1302 {
		return
	}

	item, _ := strconv.Atoi(m.Tokens["item"])
	ctx.pathItems[item] = m.Tokens["name"]
}

func parseProctitleEvent(ctx *auditFIMContext, m AuditMessageTokenMap) {
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
