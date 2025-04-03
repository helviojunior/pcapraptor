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

package ntpcalc

import (
    "time"
    "io"
    "errors"
    "os"

    //"github.com/helviojunior/pcapraptor/pkg/log"

    "github.com/helviojunior/pcapraptor/pkg/gopcap"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
)

type Writer struct {
    FileHandle *os.File
}

type NTPData struct {
	RequestTransTime   uint64
    RequestTsSec       int64
    RequestTsUsec      int64
    RequestNtpTs       time.Time
}

func NewNTPData(packetTsSec int32, packetTsUsec int32, ntpTs uint64) *NTPData {
	return &NTPData{
		RequestTsSec           	: int64(packetTsSec),
		RequestTsUsec 			: int64(packetTsUsec),
		RequestTransTime 		: ntpTs,
		RequestNtpTs 			: ntpToUnix(ntpTs),
	}
}

//https://www.ntp.org/reflib/time/
//https://www.ntp.org/reflib/y2k/
/*
Timestamp calculations are carefully constructed to avoid overflow while preserving precision. The only arithmetic operation permitted on raw timestamps is subtraction, which produces signed 64-bit timestamp differences from 68 years in the past to 68 years in the future.

All of the timestamp calculations discussed in this document involve differences between timestamps recorded at events such as the arrival or departure of an NTP packet. As described in previous sections of this document, the calculations apply whether or not the differences span none, one or more eras. The crucial distinction is whether the client clock is set within 68 years of the server clock before the protocol is started.

As in the protocol specification, let T1 be the client timestamp on the request packet, T2 the server timestamp upon arrival, T3 the server timestamp on departure of the reply packet and T4 the client timestamp upon arrival. The NTP on-wire protocol calculates the clock offset

offset = [(T2 - T1) + (T3 - T4)] / 2

and roundtrip delay

delay = (T4 - T1) - (T3 - T2)
*/

func (ntp NTPData) CalcDelta(packetTsSec int32, packetTsUsec int32, ntpTs uint64) int64 {
	t1 := time.Unix(ntp.RequestTsSec, ntp.RequestTsUsec)
	t2 := time.Unix(int64(packetTsSec), int64(packetTsUsec))
	
    d1 := int64(t2.Sub(t1).Nanoseconds() / 2)
    d2 := ntpToUnix(ntpTs).Sub(t2)
    //offset := int64((d1.Nanoseconds() + d2.Nanoseconds()) / 2)
    offset := int64(d2.Nanoseconds()) + d1

	return offset
}

func GetFileDelta(pcapFile string) (*time.Duration, error) {
    // create reader
    r, err := gopcap.Open(pcapFile)
    if err != nil {
        return nil, err
    }
    defer r.Close()

    ntpList := []*NTPData{}
    var diff time.Duration
    // loop over packets

    not_found := true
    for not_found {
        h, data, err := r.ReadNextPacket()
        if err != nil {
            if err == io.EOF {
                break
            }
            return nil, err
        }

        packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
        if ntpLayer := packet.Layer(layers.LayerTypeNTP); ntpLayer != nil {
            ntp := ntpLayer.(*layers.NTP)
            if ntp.Mode == 3 || ntp.Mode == 1 { //Request, Symetric Active
                ntpList = append(ntpList, NewNTPData(h.TsSec, h.TsUsec, uint64(ntp.TransmitTimestamp)))
            }else if ntp.Mode == 4 { // Response from server
                for _, nd := range ntpList {
                    if nd.RequestTransTime == uint64(ntp.OriginTimestamp) {
                        t := nd.CalcDelta(h.TsSec, h.TsUsec, uint64(ntp.TransmitTimestamp))
                        diff = time.Duration(t)
                        not_found = false

                        //newData := time.Unix(int64(h.TsSec), int64(h.TsUsec)).Add(dur)

                        //log.Info("NTP response found", "TsSec", h.TsSec, "pkt", h.TsUsec, "tf", newData, "t", t)
                    }
                }
                
            }
        }

    } 

    if not_found {
        return nil, errors.New("Cannot find any NTP package")
    }

    return &diff, nil
}

func ntpToUnix(ntp uint64) time.Time {
    const ntpEpochOffset = 2208988800 // seconds between 1900 and 1970

    // Extract seconds and fractional part
    seconds := uint32(ntp >> 32)
    fraction := uint32(ntp & 0xFFFFFFFF)

    // Convert fraction to nanoseconds
    nanoseconds := (uint64(fraction) * 1e9) >> 32

    // Convert to Unix time
    unixSeconds := int64(seconds) - ntpEpochOffset
    return time.Unix(unixSeconds, int64(nanoseconds))
}