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

//go:build windows

package ascii

func GetNextSpinner(spin string) string { 
	switch spin {
	    case "[=====]":
	        return "[ ====]"
	    case  "[ ====]":
	        return "[  ===]"
	    case  "[  ===]":
	        return "[=  ==]"
	    case "[=  ==]":
	        return "[==  =]"
	    case  "[==  =]":
	        return "[===  ]"
	    case "[===  ]":
	        return "[==== ]"
	    default:
	        return "[=====]"
	}
}

func ColoredSpin(spin string) string { 
	return spin
}