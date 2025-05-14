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
    "encoding/binary"
    "fmt"
    "net"
    "sort"
)


type ipNetGroup []net.IPNet

func ipToUint32(ip net.IP) uint32 {
    return binary.BigEndian.Uint32(ip.To4())
}

func uint32ToIP(n uint32) net.IP {
    ip := make(net.IP, 4)
    binary.BigEndian.PutUint32(ip, n)
    return ip
}

func commonPrefix(a, b uint32) int {
    diff := a ^ b
    prefix := 0
    for i := 31; i >= 0; i-- {
        if diff&(1<<i) != 0 {
            break
        }
        prefix++
    }
    return prefix
}

func CalculateSupernet(ips []net.IPNet) *net.IPNet {
    if len(ips) == 0 {
        return nil
    }

    min := ipToUint32(ips[0].IP)
    max := ipToUint32(ips[0].IP)

    for _, ipnet := range ips[1:] {
        ip := ipToUint32(ipnet.IP)
        if ip < min {
            min = ip
        }
        if ip > max {
            max = ip
        }
    }

    prefix := commonPrefix(min, max)
    mask := net.CIDRMask(prefix, 32)
    network := uint32ToIP(min & binary.BigEndian.Uint32(mask))

    return &net.IPNet{IP: network, Mask: mask}
}

// agrupa IPs por faixa privada
func getPrivateRange(ip net.IP) string {
    if ip[0] == 10 {
        return "10.0.0.0/8"
    }
    if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
        return "172.16.0.0/12"
    }
    if ip[0] == 192 && ip[1] == 168 {
        return "192.168.0.0/16"
    }
    return "other"
}

func GroupSubnets(subnets []string) [][]net.IPNet {
    grouped := map[string][]net.IPNet{}

    // Parse e agrupa por faixa privada
    for _, cidr := range subnets {
        _, ipnet, err := net.ParseCIDR(cidr)
        if err != nil {
            fmt.Println("Erro CIDR:", cidr)
            continue
        }
        r := getPrivateRange(ipnet.IP)
        grouped[r] = append(grouped[r], *ipnet)
    }

    // Quebra por distância > 2 /24
    var result [][]net.IPNet
    for _, group := range grouped {
        sort.Slice(group, func(i, j int) bool {
            return ipToUint32(group[i].IP) < ipToUint32(group[j].IP)
        })

        var temp []net.IPNet
        for i, subnet := range group {
            if i == 0 {
                temp = append(temp, subnet)
                continue
            }
            prev := ipToUint32(group[i-1].IP)
            curr := ipToUint32(subnet.IP)

            // distância entre /24s > 2
            if (curr - prev) > 512 {
                result = append(result, temp)
                temp = []net.IPNet{subnet}
            } else {
                temp = append(temp, subnet)
            }
        }
        if len(temp) > 0 {
            result = append(result, temp)
        }
    }

    return result
}
