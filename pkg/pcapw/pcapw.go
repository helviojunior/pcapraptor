/*
 * PACP - PCAP file writer in Golang
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
    "encoding/binary"
    //"fmt"
    //"io"
    "os"

    "github.com/dreadl0ck/gopcap"
)

/////////////////////////////
// Reader
/////////////////////////////

// Reader struct
type Writer struct {
    FileHandle *os.File
}

// Open pcap file
func Open(filename string, fileHeader gopcap.FileHeader) (*Writer, error) {

    var (
        w   = &Writer{}
        err error
    )

    w.FileHandle, err = os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return nil, err
    }

    var buff []byte
    buff = make([]byte, 24)

    binary.LittleEndian.PutUint32(buff[0:], fileHeader.MagicNumber)
    binary.LittleEndian.PutUint16(buff[4:], fileHeader.VersionMajor)
    binary.LittleEndian.PutUint16(buff[6:], fileHeader.VersionMinor)
    binary.LittleEndian.PutUint32(buff[8:], uint32(fileHeader.Thiszone))
    binary.LittleEndian.PutUint32(buff[12:], fileHeader.Sigfigs)
    binary.LittleEndian.PutUint32(buff[16:], fileHeader.Snaplen)
    binary.LittleEndian.PutUint32(buff[20:], fileHeader.Network)  

    w.FileHandle.Write(buff)

    return w, nil
}

// WritePacket write packet. returns header,data,error
func (w *Writer) WritePacket(header gopcap.PacketHeader, data []byte) error {

    var buff []byte
    buff = make([]byte, 16)
    
    binary.LittleEndian.PutUint32(buff[0:], uint32(header.TsSec))
    binary.LittleEndian.PutUint32(buff[4:], uint32(header.TsUsec))
    binary.LittleEndian.PutUint32(buff[8:], uint32(len(data)))
    binary.LittleEndian.PutUint32(buff[12:], uint32(header.OriginalLen))

    if _, err := w.FileHandle.Write(buff); err != nil {
        return err
    }

    if _, err := w.FileHandle.Write(data); err != nil {
        return err
    }

    return nil
}

// Close pcap file
func (w *Writer) Close() error {
    return w.FileHandle.Close()
}
