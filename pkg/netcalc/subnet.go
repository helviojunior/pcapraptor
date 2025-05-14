/*
 * PACP - PCAP manipulation tool in Golang
 * Copyright (c) 2025 Helvio Junior <helvio_junior [at] hotmail [dot] com>
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

package netcalc

import (
    "net"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    //"github.com/helviojunior/pcapraptor/pkg/log"

)


var privateSubnets = []net.IPNet{
        {
            IP:   net.IPv4(10, 0, 0, 0),
            Mask: net.CIDRMask(8, 32), 
        },
        {
            IP:   net.IPv4(192, 168, 0, 0),
            Mask: net.CIDRMask(16, 32), 
        },
        {
            IP:   net.IPv4(172, 16, 0, 0),
            Mask: net.CIDRMask(12, 32), 
        },
    }

var deniedSubnets = []net.IPNet{
        {
            IP:   net.IPv4(127, 0, 0, 0),
            Mask: net.CIDRMask(8, 32), // 255.0.0.0
        },
        {
            IP:   net.IPv4(169, 254, 0, 0),
            Mask: net.CIDRMask(16, 32), // 255.255.0.0
        },
        {
            IP:   net.IPv4(0, 0, 0, 0),
            Mask: net.CIDRMask(8, 32), // 255.0.0.0
        },
        {
            IP:   net.IPv4(224, 0, 0, 0),
            Mask: net.CIDRMask(3, 32), // 224.0.0.0
        },
    }

type SubnetData struct {
    SrcNet             string
    SrcMask            int16
    SrcIsPrivate       bool
    DstNet             string
    DstMask            int16
    DstIsPrivate       bool
}

func IsPrivateIP(ip net.IP) bool {
    for _, subnet := range privateSubnets {
        if subnet.Contains(ip) {
            return true
        }
    }
    return false
}

func GetSubnetsFromPacket(packet gopacket.Packet) *SubnetData {

    sIP := net.IP{ 0, 0, 0, 0 }
    dIP := net.IP{ 0, 0, 0, 0 }

    //Try to parse if is an ARP packet
    if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
        arp := arpLayer.(*layers.ARP)
        if arp.Protocol == 0x0800 { // IPv4

            sIP = net.IP{ arp.SourceProtAddress[0], arp.SourceProtAddress[1], arp.SourceProtAddress[2], arp.SourceProtAddress[3] }
            dIP = net.IP{ arp.DstProtAddress[0], arp.DstProtAddress[1], arp.DstProtAddress[2], arp.DstProtAddress[3] }

        }
    }

    if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
        ipv4 := ipLayer.(*layers.IPv4)  
        sIP = net.IP{ ipv4.SrcIP[0], ipv4.SrcIP[1], ipv4.SrcIP[2], ipv4.SrcIP[3] }
        dIP = net.IP{ ipv4.DstIP[0], ipv4.DstIP[1], ipv4.DstIP[2], ipv4.DstIP[3] }
    }

    if isDeniedIP(sIP) && isDeniedIP(dIP) {
        return nil
    }

    defaultMask := net.CIDRMask(24, 32)

    dt := &SubnetData{
        SrcNet: sIP.Mask(defaultMask).String(),
        SrcMask: 24,
        SrcIsPrivate: IsPrivateIP(sIP),
        DstNet: dIP.Mask(defaultMask).String(),
        DstMask: 24,
        DstIsPrivate: IsPrivateIP(dIP),
    }

    if dt.SrcNet == "0.0.0.0" {
        dt.SrcNet = dt.DstNet
        dt.SrcMask = dt.DstMask
        dt.SrcIsPrivate = dt.DstIsPrivate
        dt.DstNet = ""
        dt.DstMask = 0
        dt.DstIsPrivate = false
    }

    if isDeniedIP(sIP) {
        dt.SrcNet = dt.DstNet
        dt.SrcMask = dt.DstMask
        dt.SrcIsPrivate = dt.DstIsPrivate
        dt.DstNet = ""
        dt.DstMask = 0
        dt.DstIsPrivate = false
    }

    if dt.DstNet == "0.0.0.0" || isDeniedIP(dIP) {
        dt.DstNet = ""
        dt.DstMask = 0
        dt.DstIsPrivate = false
    }

    if dt.SrcNet != "" && dt.DstNet != "" {
        return dt
    }

    return nil;
}

func isDeniedIP(ip net.IP) bool {
    for _, subnet := range deniedSubnets {
        if subnet.Contains(ip) {
            return true
        }
    }
    return false
}