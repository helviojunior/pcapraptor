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

//go:build darwin || dragonfly
// +build darwin dragonfly

package disk

import (
    "fmt"
    "syscall"
)

// GetInfo returns total and free bytes available in a directory, e.g. `/`.
func GetInfo(path string, _ bool) (info Info, err error) {
    s := syscall.Statfs_t{}
    err = syscall.Statfs(path, &s)
    if err != nil {
        return Info{}, err
    }
    reservedBlocks := s.Bfree - s.Bavail
    info = Info{
        Total:  uint64(s.Bsize) * (s.Blocks - reservedBlocks),
        Free:   uint64(s.Bsize) * s.Bavail,
        Files:  s.Files,
        Ffree:  s.Ffree,
        FSType: getFSType(s.Fstypename[:]),
    }
    if info.Free > info.Total {
        return info, fmt.Errorf("detected free space (%d) > total drive space (%d), fs corruption at (%s). please run 'fsck'", info.Free, info.Total, path)
    }
    info.Used = info.Total - info.Free
    return info, nil
}


// getFSType returns the filesystem type of the underlying mounted filesystem
func getFSType(fstype []int8) string {
    b := make([]byte, len(fstype))
    for i, v := range fstype {
        b[i] = byte(v)
    }
    return string(b)
}