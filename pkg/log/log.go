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

package log

import (
    "os"
    "fmt"
    //"io"
    //"bufio"
    //"runtime"
    

    //"github.com/helviojunior/pcapraptor/internal/ascii"
    "github.com/charmbracelet/lipgloss"
    "github.com/charmbracelet/log"
    //"github.com/muesli/termenv"
    //"golang.org/x/sys/unix"
)

// LLogger is a charmbracelet logger type redefinition
type LLogger = log.Logger

// Logger is this package level logger
var Logger *LLogger
var logFilePath string
var bl string

func init() {
    styles := log.DefaultStyles()
    styles.Keys["err"] = lipgloss.NewStyle().Foreground(lipgloss.Color("204"))
    styles.Values["err"] = lipgloss.NewStyle().Bold(true)

    Logger = log.NewWithOptions(os.Stderr, log.Options{
        ReportTimestamp: false,
    })
    Logger.SetStyles(styles)
    Logger.SetLevel(log.InfoLevel)
}

func writeDataToFile(data []byte) {
    if logFilePath == "" {
        return
    }

    // Open the file in append mode, create it if it doesn't exist
    file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return
    }
    defer file.Close()

    file.Write(data)

}

func writeTextToFile(msg string) {
    if logFilePath == "" {
        return
    }

    // Open the file in append mode, create it if it doesn't exist
    file, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
    if err != nil {
        return
    }
    defer file.Close()

    file.WriteString(msg)

}

// EnableDebug enabled debug logging and caller reporting
func EnableDebug() {
    Logger.SetLevel(log.DebugLevel)
    Logger.SetReportCaller(true)
}

// EnableSilence will silence most logs, except this written with Print
func EnableSilence() {
    Logger.SetLevel(log.FatalLevel + 100)
}

// Debug logs debug messages
func Debug(msg string, keyvals ...interface{}) {
    Logger.Helper()
    Logger.Debug(msg, keyvals...)
}
func Debugf(format string, a ...interface{}) {
    Logger.Helper()
    Logger.Debug(fmt.Sprintf(format, a...) )
}

// Info logs info messages
func Info(msg string, keyvals ...interface{}) {
    Logger.Helper()
    Logger.Info(msg, keyvals...)
}
func Infof(format string, a ...interface{}) {
    Logger.Helper()
    Logger.Info(fmt.Sprintf(format, a...) )
}


// Warn logs warning messages
func Warn(msg string, keyvals ...interface{}) {
    Logger.Helper()
    Logger.Warn(msg, keyvals...)
}
func Warnf(format string, a ...interface{}) {
    Logger.Helper()
    Logger.Warn(fmt.Sprintf(format, a...) )
}


// Error logs error messages
func Error(msg string, keyvals ...interface{}) {
    Logger.Helper()
    Logger.Error(msg, keyvals...)
}
func Errorf(format string, a ...interface{}) {
    Logger.Helper()
    Logger.Error(fmt.Sprintf(format, a...) )
}

// Fatal logs fatal messages and panics
func Fatal(msg string, keyvals ...interface{}) {
    Logger.Helper()
    Logger.Fatal(msg, keyvals...)
}
func Fatalf(format string, a ...interface{}) {
    Logger.Helper()
    Logger.Fatal(fmt.Sprintf(format, a...) )
}


// Print logs messages regardless of level
func Print(msg string, keyvals ...interface{}) {
    Logger.Helper()
    Logger.Print(msg, keyvals...)
}
func Printf(format string, a ...interface{}) {
    Logger.Helper()
    Logger.Print(fmt.Sprintf(format, a...) )
}

// With returns a sublogger with a prefix
func With(keyvals ...interface{}) *LLogger {
    return Logger.With(keyvals...)
}