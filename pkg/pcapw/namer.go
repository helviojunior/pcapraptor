/*
 * PACP - PCAP renamer writer in Golang
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

package pcapw

import (
    //"bufio"
    "strings"
    "io"
    "time"
    "path/filepath"

    "github.com/dreadl0ck/gopcap"
)

/////////////////////////////
// Reader
/////////////////////////////

// Reader struct
type PcapNamer struct {
    OriginalName 		string
    Prefix 				string
    FirstPackageHeader 	*gopcap.PacketHeader
    TimeDiff 			time.Duration
}

func NewPcapNamer(filename string) (*PcapNamer, error) {
	return NewPcapNamerWithPrefix(filename, "")
}

func NewPcapNamerWithPrefix(filename string, prefix string) (*PcapNamer, error) {
	newItem := &PcapNamer{
		OriginalName   	: filename,
		Prefix 			: prefix,
		TimeDiff 		: 0,
	}
	    // create reader
    r, err := gopcap.Open(filename)
    if err != nil {
        return nil, err
    }
    defer r.Close()

    for {
        h, _, err := r.ReadNextPacket()
        if err != nil {
            if err == io.EOF {
                break
            }
            return nil, err
        }

        newItem.FirstPackageHeader = &h
        break
    }

    return newItem, nil
}

func (n *PcapNamer) GetNameFromTime() string {

	dir := filepath.Dir(n.OriginalName)
	ext := filepath.Ext(n.OriginalName)
	name := strings.TrimSuffix(filepath.Base(n.OriginalName), ext)
	if n.Prefix == "" {
		n.Prefix = name
	}

	if n.FirstPackageHeader == nil {
		return filepath.Join(dir, name + "_" + time.Now().Format("20060102_150405") + ext)
	}

    newTime := (time.Unix(int64(n.FirstPackageHeader.TsSec), int64(n.FirstPackageHeader.TsUsec))).Add(n.TimeDiff)

    return filepath.Join(dir, n.Prefix + "_" + newTime.Format("20060102_150405") + ext)
}


