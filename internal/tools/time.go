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

package tools

import (
	"time"
	"fmt"
)

// Float64ToTime takes a float64 as number of seconds since unix epoch and returns time.Time
//
// example field where this is used (expires field):
//
//	https://chromedevtools.github.io/devtools-protocol/tot/Network/#type-Cookie
func Float64ToTime(f float64) time.Time {
	if f == 0 {
		// Return zero value for session cookies
		return time.Time{}
	}
	return time.Unix(0, int64(f*float64(time.Second)))
}

func FormatDuration(d time.Duration) string {

	out := ""
    hours := int(d.Hours())
    minutes := int(d.Minutes()) % 60
    seconds := int(d.Seconds()) % 60
    milliseconds := int(d.Milliseconds()) % 60000

    if hours > 24 * 365 {
    	year := int(hours / (24 * 365))
    	out += fmt.Sprintf("%02dy ", year)
    	hours %= (24 * 365)
    }

    if hours > 24 {
    	day := int(hours / 24)
    	out += fmt.Sprintf("%02dd ", day)
    	hours %= 24
    }

    return fmt.Sprintf("%s%02dh %02dm %02ds %06dms", out, hours, minutes, seconds, milliseconds)
}