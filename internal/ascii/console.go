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

//go:build !windows
// +build !windows

package ascii

import (
    "fmt"
    "os"
)

// Show the cursor if it was hidden previously.
// Don't forget to show the cursor at least at the end of your application.
// Otherwise the user might have a terminal with a permanently hidden cursor, until they reopen the terminal.
func ShowCursor() {
    fmt.Fprint(os.Stderr, "\x1b[?25h")
}

// Hide the cursor.
// Don't forget to show the cursor at least at the end of your application with Show.
// Otherwise the user might have a terminal with a permanently hidden cursor, until they reopen the terminal.
func HideCursor() {
	fmt.Fprintf(os.Stderr, "\x1b[?25l")
}

// ClearLine clears the current line and moves the cursor to it's start position.
func ClearLine() {
	fmt.Fprintf(os.Stderr, "\x1b[2K")
}

// Clear clears the current position and moves the cursor to the left.
func Clear() {
	fmt.Fprintf(os.Stderr, "\x1b[K")
}