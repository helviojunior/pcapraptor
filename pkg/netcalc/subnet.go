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
    "github.com/helviojunior/pcapraptor/pkg/log"

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
    Net             string
    Mask            int
    IsPrivate       bool
}

func IsPrivateIP(ip net.IP) bool {
    for _, subnet := range privateSubnets {
        if subnet.Contains(ip) {
            return true
        }
    }
    return false
}

func NewSubnetFromIP(ip net.IP) SubnetData {
    return SubnetData{
        Net: ip.Mask(net.CIDRMask(24, 32)).String(),
        Mask: 24,
        IsPrivate: IsPrivateIP(ip),
    }

}

func NewSubnetFromIPMask(ip net.IP, cidr int) SubnetData {
    return SubnetData{
        Net: ip.Mask(net.CIDRMask(cidr, 32)).String(),
        Mask: cidr,
        IsPrivate: IsPrivateIP(ip),
    }
}

func AddSlice(subnetList *[]SubnetData, data SubnetData) {
    if data.Net == "" || data.Net == "0.0.0.0" {
        return
    }

    ip := net.ParseIP(data.Net)
    if ip == nil {
        return
    }

    if isDeniedIP(ip) {
        return
    }

    for _, subnet := range *subnetList {
        if subnet.Net == data.Net && subnet.Mask == data.Mask {
            return
        }
    }

    *subnetList = append(*subnetList, data)
}

func GetSubnetsFromPacket(packet gopacket.Packet) []SubnetData {

    subnetList := []SubnetData{}

    defaultMask := net.CIDRMask(24, 32)

    //Try to parse if is an ARP packet
    if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
        arp := arpLayer.(*layers.ARP)
        if arp.Protocol == 0x0800 { // IPv4    && arp.Operation == layers.ARPReply {
            AddSlice(&subnetList, NewSubnetFromIP(net.IP{ arp.SourceProtAddress[0], arp.SourceProtAddress[1], arp.SourceProtAddress[2], arp.SourceProtAddress[3] }))
            AddSlice(&subnetList, NewSubnetFromIP(net.IP{ arp.DstProtAddress[0], arp.DstProtAddress[1], arp.DstProtAddress[2], arp.DstProtAddress[3] }))
        }
    }

    if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
        ipv4 := ipLayer.(*layers.IPv4)  
        
        //TCP
        if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
            tcp := tcpLayer.(*layers.TCP)
            if tcp.ACK && !(tcp.FIN || tcp.RST) {
                AddSlice(&subnetList, NewSubnetFromIP(net.IP{ ipv4.SrcIP[0], ipv4.SrcIP[1], ipv4.SrcIP[2], ipv4.SrcIP[3] }))
                AddSlice(&subnetList, NewSubnetFromIP(net.IP{ ipv4.DstIP[0], ipv4.DstIP[1], ipv4.DstIP[2], ipv4.DstIP[3] }))
            }
        }

        //DHCP
        if dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4); dhcpLayer != nil {
            dhcp := dhcpLayer.(*layers.DHCPv4)
            if dhcp.Operation == layers.DHCPOpReply {
                isOffer := false
                for _, o := range dhcp.Options {
                    if o.Type == layers.DHCPOptMessageType && (layers.DHCPMsgType(o.Data[0]) == layers.DHCPMsgTypeOffer || layers.DHCPMsgType(o.Data[0]) == layers.DHCPMsgTypeAck) {
                        isOffer = true
                    }
                }
                
                if isOffer {
                    router := dhcp.YourClientIP
                    for _, o := range dhcp.Options {
                        if o.Type == layers.DHCPOptSubnetMask {
                            defaultMask = net.IPv4Mask(o.Data[0], o.Data[1], o.Data[2], o.Data[3])
                        }
                    }
                    ones, _ := defaultMask.Size()

                    AddSlice(&subnetList, NewSubnetFromIPMask(dhcp.YourClientIP, ones))

                    for _, o := range dhcp.Options {
                        if o.Type == layers.DHCPOptRouter {
                            router = net.IP{ o.Data[0], o.Data[1], o.Data[2], o.Data[3] }
                            AddSlice(&subnetList, NewSubnetFromIPMask(router, ones))
                        }else if o.Type  == layers.DHCPOptNameServer || o.Type == layers.DHCPOptDNS {
                            offset := 0
                            size := len(o.Data)
                            for offset <= size - 4 {
                                AddSlice(&subnetList, NewSubnetFromIP(net.IP{ o.Data[offset], o.Data[offset + 1], o.Data[offset + 2], o.Data[offset + 3] }))
                                offset += 4
                            }
                            
                        }
                    }

                    log.Debug("DHCP Offer/ACK", "IP", dhcp.YourClientIP, "Mask", net.IP(defaultMask).String(), "Router", router)
                }
            }
        }

        //TODO: Implement NBNS, LLMNR and MDNS
    }

    return subnetList;
}

func isDeniedIP(ip net.IP) bool {
    for _, subnet := range deniedSubnets {
        if subnet.Contains(ip) {
            return true
        }
    }
    return false
}
