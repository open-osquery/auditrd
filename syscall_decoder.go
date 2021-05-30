package auditrd

import (
	"bytes"
	"encoding/hex"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

type eventMetadata struct {
	Type AuditEventType `json:"-"`
	Seq  int            `json:"-"`
	Time string         `json:"-"`
}

//go:generate gomodifytags -file $GOFILE -struct ProcessEvent -add-tags json -w -skip-unexported
type ProcessEvent struct {
	eventMetadata
	Pid     int    `json:"pid"`
	Syscall string `json:"syscall"`
	Path    string `json:"path"`
	Cmdline string `json:"cmdline"`
	Cwd     string `json:"cwd"`
	Exit    int    `json:"exit"`
	Auid    int    `json:"auid"`
	Uid     int    `json:"uid"`
	Euid    int    `json:"euid"`
	Suid    int    `json:"suid"`
	Fsuid   int    `json:"fsuid"`
	Gid     int    `json:"gid"`
	Egid    int    `json:"egid"`
	Sgid    int    `json:"sgid"`
	Fsgid   int    `json:"fsgid"`
	Ppid    int    `json:"ppid"`
}

func (ae *ProcessEvent) Type() AuditEventType {
	return ae.eventMetadata.Type
}

func (ae *ProcessEvent) Seq() int {
	return ae.eventMetadata.Seq
}

func (ae *ProcessEvent) Time() string {
	return ae.eventMetadata.Time
}

//go:generate gomodifytags -file $GOFILE -struct FIMEvent -add-tags json -w -skip-unexported
type FIMEvent struct {
	eventMetadata
	Pid        int    `json:"pid"`
	Ppid       int    `json:"ppid"`
	Operation  string `json:"operation"`
	Exectuable string `json:"exectuable"`
	Cwd        string `json:"cwd"`
	Path       string `json:"path"`
	DestPath   string `json:"dest_path"`
	Uid        int    `json:"uid"`
	Gid        int    `json:"gid"`
	Auid       int    `json:"auid"`
	Euid       int    `json:"euid"`
	Egid       int    `json:"egid"`
	Fsuid      int    `json:"fsuid"`
	Fsgid      int    `json:"fsgid"`
	Suid       int    `json:"suid"`
	Sgid       int    `json:"sgid"`
}

func (pe *FIMEvent) Type() AuditEventType {
	return pe.eventMetadata.Type
}

func (pe *FIMEvent) Seq() int {
	return pe.eventMetadata.Seq
}

func (pe *FIMEvent) Time() string {
	return pe.eventMetadata.Time
}

type syscallContext struct {
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
	destPath  string
	pathItems [5]string

	// Event type which shall be inferred from the events it contains
	eventType string
}

// eventParsers is a map that holds functions that contains parser for different
// audit message types which take in a parsed audit message token map and
// populates the Audit context passed to it.
var syscallEventParsers = map[uint16]func(*syscallContext, map[string]string){
	1300: parseSyscallRecord,
	1302: parsePathRecord,
	1307: parseCwdRecord,
	1327: parseProctitleRecord,
}

var (
	syscallContextPool = &sync.Pool{
		New: func() interface{} {
			return new(syscallContext)
		},
	}
)

func (ctx *syscallContext) reset() {
	ctx.auid, ctx.uid, ctx.euid, ctx.fsuid, ctx.suid = 0, 0, 0, 0, 0
	ctx.gid, ctx.egid, ctx.fsgid, ctx.sgid = 0, 0, 0, 0
	ctx.executable, ctx.comm, ctx.tty, ctx.arch, ctx.success = "", "", "", "", ""
	ctx.syscall, ctx.pid, ctx.ppid, ctx.ses, ctx.exit = -1, 0, -1, 0, 0
	ctx.proctitle = ""
	ctx.cwd, ctx.path, ctx.destPath = "", "", ""
	for i := range ctx.pathItems {
		ctx.pathItems[i] = ""
	}
}

func ParseSyscallEvent(amg *AuditMessageGroup) (AuditEvent, AuditEventType) {
	ctx := syscallContextPool.Get().(*syscallContext)
	ctx.reset()
	defer syscallContextPool.Put(ctx)

	for _, msg := range amg.Msgs {
		if parser, ok := syscallEventParsers[msg.Type]; ok {
			fields := tokenize(msg.Data)
			parser(ctx, fields)
		}
	}

	if isExecSyscall(ctx.syscall) {
		evt := makeProcessEvent(ctx)
		evt.eventMetadata = eventMetadata{
			Process,
			amg.Seq,
			amg.AuditTime,
		}

		return evt, Process
	} else if isFIMSyscall(ctx.syscall) {
		evt := makeFIMEvent(ctx)
		evt.eventMetadata = eventMetadata{
			FIM,
			amg.Seq,
			amg.AuditTime,
		}

		return evt, FIM
	}

	// TODO: implement an unknown audit event type that contains the raw event
	// of the parsed fields maybe.
	return nil, Unknown
}

func makeProcessEvent(ctx *syscallContext) *ProcessEvent {
	e := &ProcessEvent{
		Pid:     ctx.pid,
		Ppid:    ctx.ppid,
		Syscall: SyscallName(ctx.syscall),
		Path:    ctx.executable,
		Cmdline: ctx.proctitle,
		Cwd:     ctx.cwd,
		Exit:    ctx.exit,
		Auid:    ctx.auid,
		Uid:     ctx.uid,
		Euid:    ctx.euid,
		Suid:    ctx.suid,
		Fsuid:   ctx.fsuid,
		Gid:     ctx.gid,
		Egid:    ctx.egid,
		Fsgid:   ctx.fsgid,
	}

	return e
}

func makeFIMEvent(ctx *syscallContext) *FIMEvent {
	// Since this a FIM event, there must be filepaths involved other than the
	// regular 2 AUDIT_PATH record. It's necessary to get those paths resolved
	// to their absolute paths for processing.
	resolvePath(ctx)

	e := &FIMEvent{
		Pid:      ctx.pid,
		Ppid:     ctx.ppid,
		Path:     ctx.executable,
		Cwd:      ctx.cwd,
		Auid:     ctx.auid,
		Uid:      ctx.uid,
		Euid:     ctx.euid,
		Suid:     ctx.suid,
		Fsuid:    ctx.fsuid,
		Gid:      ctx.gid,
		Egid:     ctx.egid,
		Fsgid:    ctx.fsgid,
		DestPath: ctx.destPath,
	}
	return e
}

func parseSyscallRecord(ctx *syscallContext, fields map[string]string) {
	ctx.syscall, _ = strconv.Atoi(fields["syscall"])
	ctx.success = fields["success"]
	ctx.exit, _ = strconv.Atoi(fields["exit"])
	ctx.ppid, _ = strconv.Atoi(fields["ppid"])
	ctx.pid, _ = strconv.Atoi(fields["pid"])

	ctx.auid, _ = strconv.Atoi(fields["auid"])
	ctx.uid, _ = strconv.Atoi(fields["uid"])
	ctx.gid, _ = strconv.Atoi(fields["gid"])
	ctx.euid, _ = strconv.Atoi(fields["euid"])
	ctx.egid, _ = strconv.Atoi(fields["egid"])
	ctx.fsuid, _ = strconv.Atoi(fields["fsuid"])
	ctx.fsgid, _ = strconv.Atoi(fields["fsgid"])
	ctx.suid, _ = strconv.Atoi(fields["suid"])
	ctx.sgid, _ = strconv.Atoi(fields["sgid"])

	ctx.ses, _ = strconv.Atoi(fields["ses"])

	ctx.tty = fields["tty"]
	ctx.comm = strings.Trim(fields["comm"], `"`)
	ctx.executable = strings.Trim(fields["exe"], `"`)
}

func parseCwdRecord(ctx *syscallContext, fields map[string]string) {
	ctx.cwd = strings.Trim(fields["cwd"], `"`)
}

func parsePathRecord(ctx *syscallContext, fields map[string]string) {
	item, _ := strconv.Atoi(fields["item"])
	ctx.pathItems[item] = fields["name"]
}

func parseProctitleRecord(ctx *syscallContext, fields map[string]string) {
	var p string = fields["proctitle"]
	if strings.HasPrefix(p, `"`) {
		ctx.proctitle = strings.Trim(p, `"`)
		return
	}

	args, _ := hex.DecodeString(p)
	ctx.proctitle = string(bytes.ReplaceAll(args, []byte{0}, []byte{' '}))
}

func resolvePath(ctx *syscallContext) {
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
		ctx.destPath = normalizePath(ctx.cwd, ctx.pathItems[1], ctx.pathItems[3])

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
		ctx.destPath = normalizePath(ctx.cwd, ctx.pathItems[1], ctx.pathItems[4])
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

func isExecSyscall(syscallNumber int) bool {
	s, ok := syscallNumberToName[syscallNumber]
	if !ok {
		return false
	}

	return s == "execve" || s == "execveat"
}

func isFIMSyscall(syscallNumber int) bool {
	_, ok := fimSyscalls[syscallNumber]
	return ok
}

func isKillSyscall(syscallNumber int) bool {
	s, ok := syscallNumberToName[syscallNumber]
	if !ok {
		return false
	}

	return s == "kill" || s == "tkill" || s == "tgkill"
}
