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
// +build windows

package log

import (
    "syscall"
    "unsafe"
    "os"
)

var (
    kernel32                       = syscall.NewLazyDLL("kernel32.dll")
    procFillConsoleOutputCharacter = kernel32.NewProc("FillConsoleOutputCharacterW")
    procGetConsoleCursorInfo       = kernel32.NewProc("GetConsoleCursorInfo")
    procGetConsoleScreenBufferInfo = kernel32.NewProc("GetConsoleScreenBufferInfo")
    procSetConsoleCursorInfo       = kernel32.NewProc("SetConsoleCursorInfo")
    procSetConsoleCursorPosition   = kernel32.NewProc("SetConsoleCursorPosition")
)

type short int16
type dword uint32
type word uint16

type coord struct {
    x short
    y short
}

type smallRect struct {
    bottom short
    left   short
    right  short
    top    short
}

type consoleScreenBufferInfo struct {
    size              coord
    cursorPosition    coord
    attributes        word
    window            smallRect
    maximumWindowSize coord
}

// ClearLine clears the current line and moves the cursor to its start position.
func clearLine() {
    handle := syscall.Handle(os.Stderr.Fd())

    var csbi consoleScreenBufferInfo
    _, _, _ = procGetConsoleScreenBufferInfo.Call(uintptr(handle), uintptr(unsafe.Pointer(&csbi)))

    var w uint32
    var x short
    cursor := csbi.cursorPosition
    x = csbi.size.x
    _, _, _ = procFillConsoleOutputCharacter.Call(uintptr(handle), uintptr(' '), uintptr(x), uintptr(*(*int32)(unsafe.Pointer(&cursor))), uintptr(unsafe.Pointer(&w)))
}
