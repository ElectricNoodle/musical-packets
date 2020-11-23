
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var iface = flag.String("i", "wlp2s0", "Interface to read packets from")

var handle *pcap.Handle
var promisc = false
var statsTime int

/*PacketFlow used to store information on each distinct flow of packets */
type PacketFlow struct {
	packets    []*layers.IPv4
	srcIP      net.IP
	dstIP      net.IP
	srcPort    uint16
	dstPort    uint16
	protocol   string
	totalBytes int64
}

var hostIP net.IP
var packetFlows map[string]*PacketFlow

func main() {
	defer util.Run()()

	statsTime = 20
	hostIP = getIPAddressInfo(*iface)

	handle = initPCAPHandle(hostIP)
	packetFlows = make(map[string]*PacketFlow)

	fmt.Printf("IP: %s\n", hostIP.String())

	getPackets(handle, statsTime)

	defer handle.Close()

}

/*initPCAPHandle Configures any options/filters on the pcap handle then returns it for use. */
func initPCAPHandle(ip net.IP) *pcap.Handle {

	var err error

	inactive, err := pcap.NewInactiveHandle(*iface)
	if err != nil {
		log.Fatalf("could not create: %v", err)
	}

	defer inactive.CleanUp()

	if err = inactive.SetPromisc(promisc); err != nil {

		log.Fatalf("could not set promisc mode: %v", err)

	} else if err = inactive.SetTimeout(time.Second); err != nil {

		log.Fatalf("could not set timeout: %v", err)
	}
	if handle, err = inactive.Activate(); err != nil {

		log.Fatal("PCAP Activate error:", err)

	}

	var filter string = "host " + ip.String()
	err = handle.SetBPFFilter(filter)

	if err != nil {
		fmt.Println(err)
		return nil
	}

	return handle
}

/*getIPAddressInfo returns the firsrt IP configured on the adapter specified. */
func getIPAddressInfo(interfaceName string) net.IP {

	i, err := net.InterfaceByName(interfaceName)

	if err != nil {
		fmt.Println(err)
		return nil
	}

	addresses, err := i.Addrs()

	if err != nil {
		fmt.Println(err)
		return nil
	}

	var ip net.IP

	switch v := addresses[0].(type) {
	case *net.IPNet:
		ip = v.IP
	case *net.IPAddr:
		ip = v.IP
	}
	return ip

}

/* getPackets handles the main loop which pulls in packets from the network packet source passed in.
   Also dumps out the packet flow map every so often.
*/
func getPackets(src gopacket.PacketDataSource, stats int) {

	var dec gopacket.Decoder
	var ok bool

	decoder := "Ethernet"

	if dec, ok = gopacket.DecodersByLayerName[decoder]; !ok {
		log.Fatalln("No decoder named", decoder)
	}

	source := gopacket.NewPacketSource(src, dec)
	source.Lazy = false
	source.NoCopy = true
	source.DecodeStreamsAsDatagrams = true

	fmt.Fprintln(os.Stderr, "Reading packets..")

	count := 0
	bytes := int64(0)

	defragger := ip4defrag.NewIPv4Defragmenter()

	for packet := range source.Packets() {

		count++
		bytes += int64(len(packet.Data()))

		processPacket(packet, defragger)

		if count%stats == 0 {

			fmt.Printf("Processed %v packets (%v bytes).\n", count, bytes)
			fmt.Printf("Packet Flows: \n")

			for _, flow := range packetFlows {
				fmt.Printf("Source: %s\t%d\tDest: \t%s\t%d\tProtocol: %s\tTotalBytes: %d\n",
					flow.srcIP.String(),
					flow.srcPort,
					flow.dstIP.String(),
					flow.dstPort,
					flow.protocol,
					flow.totalBytes)
			}
			fmt.Printf("%d Unique flows.\n", len(packetFlows))
		}
	}
}

/* processPacket parses the packet depending on which protocol it is and hands it to processFlow */
func processPacket(packet gopacket.Packet, defragger *ip4defrag.IPv4Defragmenter) {

	/* Handles defragmentation */
	ip4Layer := packet.Layer(layers.LayerTypeIPv4)

	if ip4Layer == nil {
		return
	}

	ip4 := ip4Layer.(*layers.IPv4)
	newip4, err := defragger.DefragIPv4(ip4)

	if err != nil {
		log.Fatalln("Error while de-fragmenting", err)
	} else if newip4 == nil {
		return
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {

		processFlow(packet, newip4, tcpLayer, "TCP")

	} else if udpLayer := packet.Layer(layers.LayerTypeUDP); udpLayer != nil {

		processFlow(packet, newip4, udpLayer, "UDP")
	}

}

/* processFlow Creates a unique key for each protocol type and either creates a new flow,
   or finds an existing one. Probably could be tidied up a bit. Should probably store packets too.
*/
func processFlow(packet gopacket.Packet, ipv4 *layers.IPv4, layer gopacket.Layer, protocol string) {

	var key1 string
	var key2 string

	var flow *PacketFlow

	if protocol == "TCP" {

		tcp, _ := layer.(*layers.TCP)

		key1 = protocol + ":" + ipv4.SrcIP.String() + ":" + tcp.SrcPort.String() + ":" + ipv4.DstIP.String() + ":" + tcp.DstPort.String()
		key2 = protocol + ":" + ipv4.DstIP.String() + ":" + tcp.DstPort.String() + ":" + ipv4.SrcIP.String() + ":" + tcp.SrcPort.String()

		flow = &PacketFlow{nil, ipv4.SrcIP, ipv4.DstIP, uint16(tcp.SrcPort), uint16(tcp.DstPort), protocol, int64(len(packet.Data()))}

	} else if protocol == "UDP" {

		udp, _ := layer.(*layers.UDP)

		key1 = protocol + ":" + ipv4.SrcIP.String() + ":" + udp.SrcPort.String() + ":" + ipv4.DstIP.String() + ":" + udp.DstPort.String()
		key2 = protocol + ":" + ipv4.DstIP.String() + ":" + udp.DstPort.String() + ":" + ipv4.SrcIP.String() + ":" + udp.SrcPort.String()

		flow = &PacketFlow{nil, ipv4.SrcIP, ipv4.DstIP, uint16(udp.SrcPort), uint16(udp.DstPort), protocol, int64(len(packet.Data()))}
	}

	if element, found := packetFlows[key1]; found {

		element.totalBytes += int64(len(packet.Data()))
		packetFlows[key1] = element

	} else if element, found := packetFlows[key2]; found {

		element.totalBytes += int64(len(packet.Data()))
		packetFlows[key2] = element

	} else {

		if hostIP.Equal(ipv4.SrcIP) {
			packetFlows[key1] = flow
		}
		if hostIP.Equal(ipv4.DstIP) {
			packetFlows[key2] = flow
		}
	}

}
