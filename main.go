package main

import (
	"arp/fakearp"
	"flag"
	"fmt"
	"github.com/google/gopacket/pcap"
	"k8s.io/klog"
	"log"
	"net"
	"strings"
	"syscall"
	"time"
	"unsafe"
)

var (
	handle *pcap.Handle
)
var ipstr string
var macstr string
var ifaceName string

func main() {

	// vm ip
	flag.StringVar(&ipstr, "ip", "2.3.4.5", "gratuitous ARP IP")
	//vm mac
	flag.StringVar(&macstr, "mac", "cc:ee:dd:d3:67:88", "gratuitous ARP Mac")
	//node iface
	flag.StringVar(&ifaceName, "i", "bond0", "gratuitous ARP Mac iface")
	flag.Parse()
	var err error
	handle, err = pcap.OpenLive(ifaceName, 65536, true, 3*time.Millisecond)
	if err != nil {
		log.Fatal(err)
	}

	defer handle.Close()
	// test
	GetNotifyArp(ifaceName)

}

func SendFakeARPRequestVM() {
	klog.Infoln("bond nic failover....")
	klog.Infoln("send gratuitous arp request....")
	src := net.ParseIP(ipstr)
	mac, err := net.ParseMAC(macstr)
	if err != nil {
		fmt.Println(err)
	}
	broadcastMac, err := net.ParseMAC("ff:ff:ff:ff:ff:ff")
	if err != nil {
		fmt.Println(err)
	}
	fakearp.SendAFakeArpRequest(handle, src, src, broadcastMac, mac)
}

func GetNotifyArp(bond string) {
	l, _ := ListenNetlink()

	for {
		msgs, err := l.ReadMsgs()
		if err != nil {
			fmt.Printf("Could not read netlink:\n %s", err) // can't find this netlink
		}
	loop:
		for _, m := range msgs {
			switch m.Header.Type {
			case syscall.NLMSG_DONE, syscall.NLMSG_ERROR:
				break loop
			case syscall.RTM_NEWLINK, syscall.RTM_DELLINK: // get netlink message
				res, err := PrintLinkMsg(&m)
				if err != nil {
					fmt.Printf("Could not find netlink %s\n", err)
				} else {
					ethInfo := strings.Fields(res)
					if ethInfo[2] == bond && ethInfo[1] == "up" {
						SendFakeARPRequestVM()
					}
				}
			}

		}
	}
}

type NetlinkListener struct {
	fd int
	sa *syscall.SockaddrNetlink
}

func ListenNetlink() (*NetlinkListener, error) { // Listen netlink
	groups := syscall.RTNLGRP_LINK
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
	if msg.Header.Type == syscall.RTM_NEWLINK {
		res = "NEWLINK: " + str + " " + eth.Name
	} else {
		res = "DELLINK: " + eth.Name
	}

	return res, nil
}

func Print() {
	klog.Warning("bond0 failover......")
}
