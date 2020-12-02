package fakearp

import (
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "k8s.io/klog"
	"net"
	"sync"
)

var (
	handleMutex sync.Mutex = sync.Mutex{}
)

//send a arp reply from srcIp to dstIP
func SendAFakeArpRequest(handle *pcap.Handle, dstIP, srcIP net.IP, dstMac, srcMac net.HardwareAddr) {

	arpLayer := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		DstHwAddress:      dstMac,
		DstProtAddress:    []byte(dstIP.To4()),
		SourceHwAddress:   srcMac,
		SourceProtAddress: []byte(srcIP.To4()),
	}

	ethernetLayer := &layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       dstMac,
		EthernetType: layers.EthernetTypeARP,
	}

	// And create the packet with the layers
	buffer := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	err := gopacket.SerializeLayers(buffer, opts,
		ethernetLayer,
		arpLayer,
	)
	if err != nil {
		log.Error(err)
	}
	outgoingPacket := buffer.Bytes()
	log.Infoln("sending arp")
	//log.Infoln(hex.Dump(outgoingPacket))
	handleMutex.Lock()
	err = handle.WritePacketData(outgoingPacket)
	handleMutex.Unlock()
	if err != nil {
		log.Error(err)
	}
}
