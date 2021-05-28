// +build linux

package auditrd

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/golang/glog"
	"github.com/josharian/native"
)

var endianness = native.Endian

const (
	// MAX_AUDIT_MESSAGE_LENGTH see https://github.com/torvalds/linux/blob/v5.6/include/uapi/linux/audit.h#L441
	MAX_AUDIT_MESSAGE_LENGTH = 8970

	AUDIT_NLGRP_READLOG = 1
)

//TODO: this should live in a marshaller
type auditStatusPayload struct {
	Mask            uint32
	Enabled         uint32
	Failure         uint32
	Pid             uint32
	RateLimit       uint32
	BacklogLimit    uint32
	Lost            uint32
	Backlog         uint32
	Version         uint32
	BacklogWaitTime uint32
}

// NetlinkPacket is an alias to give the header a similar name here
type netlinkPacket syscall.NlMsghdr

// The audit message client interface
type Client interface {
	Send(*netlinkPacket, *auditStatusPayload) error
	Receive() (*syscall.NetlinkMessage, error)
}

type netlinkClient struct {
	fd      int
	address syscall.Sockaddr
	seq     uint32
	buf     []byte
}

// NewNetlinkClient creates a client to the audit netlink socket to read the
// audit logs. This accepts a parameter, readonly, which tells the client to
// bind it's PID or not not. If the client does not bind it's PID, it needs to
// connect to the socket in the read only group. Note that this flag should only
// be used in Linux Kernel version v3.16 or above.
func NewNetlinkClient(recvSize int, readonly bool) (Client, error) {
	fd, err := syscall.Socket(
		syscall.AF_NETLINK, syscall.SOCK_RAW, syscall.NETLINK_AUDIT)
	if err != nil {
		return nil, fmt.Errorf("Could not create a socket: %s", err)
	}

	var groups uint32 = 0
	if readonly {
		groups = AUDIT_NLGRP_READLOG
	}

	n := &netlinkClient{
		fd: fd,
		address: &syscall.SockaddrNetlink{
			Family: syscall.AF_NETLINK,
			Groups: groups,
			Pid:    0,
		},
		buf: make([]byte, MAX_AUDIT_MESSAGE_LENGTH),
	}

	if err = syscall.Bind(fd, n.address); err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("Could not bind to netlink socket: %s", err)
	}

	// Set the buffer size if we were asked
	if recvSize > 0 {
		err := syscall.SetsockoptInt(
			fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, recvSize)
		if err != nil {
			glog.Error("Failed to set receive buffer size")
		}
	}

	// Print the current receive buffer size
	v, err := syscall.GetsockoptInt(
		n.fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err == nil {
		glog.V(2).Infoln("Socket receive buffer size:", v)
	}

	if !readonly {
		// If a readonly connection is needed and supported, don't run the keep
		// connection worker.
		go func() {
			for {
				// Attempt to keep the audit connection
				n.KeepConnection()
				time.Sleep(time.Second * 5)
			}
		}()
	}

	return n, nil
}

// Send will send a packet and payload to the netlink socket without waiting for
// a response
func (n *netlinkClient) Send(np *netlinkPacket, a *auditStatusPayload) error {
	//We need to get the length first. This is a bit wasteful, but requests are
	//rare so yolo..
	buf := new(bytes.Buffer)
	var length int

	np.Seq = atomic.AddUint32(&n.seq, 1)

	for {
		buf.Reset()
		binary.Write(buf, endianness, np)
		binary.Write(buf, endianness, a)
		if np.Len == 0 {
			length = len(buf.Bytes())
			np.Len = uint32(length)
		} else {
			break
		}
	}

	if err := syscall.Sendto(n.fd, buf.Bytes(), 0, n.address); err != nil {
		return err
	}

	return nil
}

// Receive will receive a packet from a netlink socket
func (n *netlinkClient) Receive() (*syscall.NetlinkMessage, error) {
	nlen, _, err := syscall.Recvfrom(n.fd, n.buf, 0)
	if err != nil {
		return nil, err
	}

	if nlen < 1 {
		return nil, errors.New("Got a 0 length packet")
	}

	msg := &syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Len:   endianness.Uint32(n.buf[0:4]),
			Type:  endianness.Uint16(n.buf[4:6]),
			Flags: endianness.Uint16(n.buf[6:8]),
			Seq:   endianness.Uint32(n.buf[8:12]),
			Pid:   endianness.Uint32(n.buf[12:16]),
		},
		Data: n.buf[syscall.SizeofNlMsghdr:nlen],
	}

	return msg, nil
}

// KeepConnection re-establishes our connection to the netlink socket
func (n *netlinkClient) KeepConnection() {
	payload := &auditStatusPayload{
		Mask:    4,
		Enabled: 1,
		Pid:     uint32(syscall.Getpid()),
		//TODO: Failure: http://lxr.free-electrons.com/source/include/uapi/linux/audit.h#L338
	}

	packet := &netlinkPacket{
		Type:  uint16(1001),
		Flags: syscall.NLM_F_REQUEST | syscall.NLM_F_ACK,
		Pid:   uint32(syscall.Getpid()),
	}

	err := n.Send(packet, payload)
	if err != nil {
		glog.Error("Error occurred while trying to keep the connection:", err)
	}
}
