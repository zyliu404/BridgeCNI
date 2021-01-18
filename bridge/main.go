package main

import (
	"fmt"
	"k8s.io/klog"
	"net"
	"syscall"
	"unsafe"
)

func main() {
	// test
	GetNotifyArp()

}

func GetNotifyArp() {
	l, _ := ListenNetlink()

	for {
		msgs, err := l.ReadMsgs()
		if err != nil {
			fmt.Printf("Could not read netlink:\n %s", err) // can't find this netlink
		}
		for _, m := range msgs {
			fmt.Println(PrintLinkMsg(&m))
			fmt.Println(m.Header)
			fmt.Println(m.Data)
			switch m.Header.Type {
			case syscall.RTM_NEWNEIGH, syscall.RTM_DELNEIGH:
				fmt.Println("get event")

			}
		}
	}
}

type NetlinkListener struct {
	fd int
	sa *syscall.SockaddrNetlink
}

func ListenNetlink() (*NetlinkListener, error) { // Listen netlink
	groups := syscall.RTNLGRP_NEIGH
	//|
	//syscall.RTNLGRP_IPV4_IFADDR |
	//syscall.RTNLGRP_IPV4_ROUTE |
	//syscall.RTNLGRP_IPV6_IFADDR |
	//syscall.RTNLGRP_IPV6_ROUTE

	s, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM,
		syscall.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("socket: %s", err)
	}

	saddr := &syscall.SockaddrNetlink{
		Family: syscall.AF_NETLINK,
		Pid:    uint32(0),
		Groups: uint32(groups),
	}

	err = syscall.Bind(s, saddr)
	if err != nil {
		return nil, fmt.Errorf("bind: %s", err)
	}

	return &NetlinkListener{fd: s, sa: saddr}, nil
}

func (l *NetlinkListener) ReadMsgs() ([]syscall.NetlinkMessage, error) { // read netlink message
	defer func() {
		recover()
	}()

	pkt := make([]byte, 2048)

	n, err := syscall.Read(l.fd, pkt)
	if err != nil {
		return nil, fmt.Errorf("read: %s", err)
	}

	msgs, err := syscall.ParseNetlinkMessage(pkt[:n])
	if err != nil {
		return nil, fmt.Errorf("parse: %s", err)
	}

	return msgs, nil
}

func PrintLinkMsg(msg *syscall.NetlinkMessage) (string, error) { // when netlink changed, function can listen the message and notify user
	defer func() {
		recover()
	}()

	var str, res string
	ifim := (*syscall.IfInfomsg)(unsafe.Pointer(&msg.Data[0]))
	eth, err := net.InterfaceByIndex(int(ifim.Index))
	if err != nil {
		return "", fmt.Errorf("LinkDev %d: %s", int(ifim.Index), err)
	}
	if eth.Flags&syscall.IFF_UP == 1 {
		str = "up"
	} else {
		str = "down"
	}
	if msg.Header.Type == syscall.RTM_DELNEIGH {
		res = "NEWLINK: " + str + " " + eth.Name
	} else {
		res = "DELLINK: " + eth.Name
	}

	return res, nil
}

func Print() {
	klog.Warning("bond0 failover......")
}
