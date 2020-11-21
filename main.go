// Copyright 2012 Google, Inc. All rights reserved.
//
// Use of this source code is governed by a BSD-style license
// that can be found in the LICENSE file in the root of the source
// tree.

// The pcapdump binary implements a tcpdump-like command line tool with gopacket
// using pcap as a backend data collection mechanism.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/examples/util"
	"github.com/google/gopacket/ip4defrag"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

var iface = flag.String("i", "eth0", "Interface to read packets from")

var handle *pcap.Handle
var promisc = true

func main() {
	defer util.Run()()

	handle = initPCAPHandle()
	getPackets(handle)

	defer handle.Close()

}

func initPCAPHandle() *pcap.Handle {

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

	return handle
}

func getPackets(src gopacket.PacketDataSource) {

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
	//start := time.Now()
	//errors := 0
	//truncated := 0
	//layertypes := map[gopacket.LayerType]int{}
	defragger := ip4defrag.NewIPv4Defragmenter()

	for packet := range source.Packets() {

		count++
		bytes += int64(len(packet.Data()))

		/* Handles defragmentation */
		ip4Layer := packet.Layer(layers.LayerTypeIPv4)

		if ip4Layer == nil {
			continue
		}

		ip4 := ip4Layer.(*layers.IPv4)
		l := ip4.Length

		newip4, err := defragger.DefragIPv4(ip4)

		if err != nil {
			log.Fatalln("Error while de-fragmenting", err)
		} else if newip4 == nil {
			continue // packet fragment, we don't have whole packet yet.
		}
		if newip4.Length != l {

			fmt.Printf("Decoding re-assembled packet: %s\n", newip4.NextLayerType())
			pb, ok := packet.(gopacket.PacketBuilder)
			if !ok {
				panic("Not a PacketBuilder")
			}
			nextDecoder := newip4.NextLayerType()
			nextDecoder.Decode(newip4.Payload, pb)

		}

		fmt.Println(packet.Dump())
		fmt.Println(packet)

	}
}
