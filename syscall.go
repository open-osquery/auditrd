package auditrd

import (
	"bytes"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/golang/glog"
	"github.com/pkg/errors"
)

var (
	syscallNameToNumber = map[string]int{}
	syscallNumberToName = map[int]string{}
	fimSyscalls         = map[int]bool{}
	mu                  sync.Mutex
)

// Generate the syscall Map on a machine at runtime using the ausyscall since
// there is no reliable way to get it at buildtime for multiple versions of
// kernels or architecture. Other way could be to list down individual syscalls
// and create a mapping using CGO which increases a buildtime dependency. This
// function assumes that the system has audit tools installed, atleast ausyscall
// to be able to generate the mapping.
func generateSyscallMap() error {
	mu.Lock()
	defer mu.Unlock()

	if len(syscallNameToNumber) != 0 {
		glog.Warningf("Syscall map already initialized")
		return nil
	}
	_, err := os.Stat("/usr/bin/ausyscall")
	if err != nil {
		return errors.Wrap(err, "Failed to find ausyscall")
	}

	cmd := exec.Command("/usr/bin/ausyscall", "--dump")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return err
	}

	rd := &out
	for {
		line, err := rd.ReadBytes('\n')
		if err != nil {
			break
		}

		tokens := bytes.Split(bytes.Trim(line, " \n"), []byte{'\t'})
		syscallNumber, _ := strconv.Atoi(string(tokens[0]))
		syscallName := strings.ToLower(string(tokens[len(tokens)-1]))

		syscallNameToNumber[syscallName] = syscallNumber
		syscallNumberToName[syscallNumber] = syscallName
	}

	generateFIMSyscalls()

	return nil
}

func SyscallName(syscallNumber int) string {
	return syscallNumberToName[syscallNumber]
}

func SyscallNumber(syscallName string) int {
	return syscallNameToNumber[strings.ToLower(syscallName)]
}

func IsExecSyscall(syscallNumber int) bool {
	s, ok := syscallNumberToName[syscallNumber]
	if !ok {
		return false
	}

	return s == "execve" || s == "execveat"
}

func IsFIMSyscall(syscallNumber int) bool {
	_, ok := fimSyscalls[syscallNumber]
	return ok
}

func generateFIMSyscalls() {
	for _, s := range []string{
		"linkat",
		"symlinkat",
		"unlinkat",
		"renameat",
		"renameat2",
		"mknodat",
		"openat",
		"open_by_handle_at",
		"name_to_handle_at",
		"close",
		"dup",
		"dup3",
		"pread64",
		"preadv",
		"read",
		"readv",
		"mmap",
		"write",
		"writev",
		"pwrite64",
		"pwritev",
		"truncate",
		"ftruncate",
		"clone",
		"symlink",
		"unlink",
		"rename",
		"creat",
		"mknod",
		"open",
		"dup2",
		"fork",
		"vfork",
	} {
		fimSyscalls[SyscallNumber(s)] = true
	}
}
