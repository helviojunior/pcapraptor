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

package cmd

import (
	"io"
    "errors"
    "time"
    "os"
    "path/filepath"
    "strings"
    "fmt"
    "sync"

    "github.com/helviojunior/pcapraptor/pkg/ntpcalc"
    "github.com/helviojunior/pcapraptor/pkg/pcapw"
    "github.com/helviojunior/pcapraptor/internal/ascii"
    "github.com/helviojunior/pcapraptor/internal/tools"
    "github.com/helviojunior/pcapraptor/pkg/log"
    "github.com/helviojunior/pcapraptor/pkg/gopcap"
    resolver "github.com/helviojunior/gopathresolver"
    "github.com/spf13/cobra"
)

var pcapFiles = struct {
    fromFile string
    toFile   string

    fromExt string
    toExt   string
}{}

type ConvStatus struct {
    Packets int
    Label string
    ShowCounter bool
    Spin string
}

func (st *ConvStatus) Print() { 
    st.Spin = ascii.GetNextSpinner(st.Spin)

    lbl := st.Label
    if st.ShowCounter {
        lbl += fmt.Sprintf(" adjusted %d packets", st.Packets)
    }

    fmt.Fprintf(os.Stderr, "%s\n %s %s\r\033[A", 
        "                                                                        ",
        ascii.ColoredSpin(st.Spin), 
        lbl)
} 

var pcapExtensions = []string{".pcap"}

var autoNtpCmd = &cobra.Command{
    Use:   "ntp",
    Short: "Look for NTP request/response into PCAP file and calculate package time shifiting",
    Long: ascii.LogoHelp(ascii.Markdown(`
# ntp

Look for NTP request/response into PCAP file and calculate package time shifiting.

A -pcap must be specified.
`)),
    Example: `
   - pcapraptor ntp --pcap data.pcap
   - pcapraptor ntp --pcap data.pcap --output-file adjusted.pcap`,
    PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
        var err error

        // Annoying quirk, but because I'm overriding PersistentPreRun
        // here which overrides the parent it seems.
        // So we need to explicitly call the parent's one now.
        if err = rootCmd.PersistentPreRunE(cmd, args); err != nil {
            return err
        }

        return nil
    },
    PreRunE: func(cmd *cobra.Command, args []string) error {
        var err error

        if pcapFiles.fromFile == "" {
            return errors.New("from file not set")
        }
        pcapFiles.fromFile, err = resolver.ResolveFullPath(pcapFiles.fromFile)
        if err != nil {
            return err
        }

        pcapFiles.fromExt = strings.ToLower(filepath.Ext(pcapFiles.fromFile))

        if pcapFiles.fromExt == "" {
            return errors.New("source files must have extensions")
        }

        if pcapFiles.toFile != "" {
                
            pcapFiles.toFile, err = resolver.ResolveFullPath(pcapFiles.toFile)
            if err != nil {
                return err
            }
            pcapFiles.toExt = strings.ToLower(filepath.Ext(pcapFiles.toFile))

            if pcapFiles.toExt == "" {
                return errors.New("destination files must have extensions")
            }

            if !tools.SliceHasStr(pcapExtensions, pcapFiles.toExt) {
                return errors.New(fmt.Sprintf("unsupported to (%s) file type", pcapFiles.toExt))
            }

            if isv, err := resolver.IsValidAndNotExists(pcapFiles.toFile); !isv {
                return err
            }
        }

        if pcapFiles.fromFile == pcapFiles.toFile {
            return errors.New("👀 source and destination files cannot be the same")
        }

        if !tools.SliceHasStr(pcapExtensions, pcapFiles.fromExt) {
            return errors.New(fmt.Sprintf("unsupported from (%s) file type", pcapFiles.fromExt))
        }
        
        return nil
    },
    Run: func(cmd *cobra.Command, args []string) {
        var running bool
        wg := sync.WaitGroup{}

        var status = &ConvStatus{
            Packets: 0,
            Label: "",
            ShowCounter: false,
            Spin: "",
        }

        running = true
        wg.Add(1)
        go func() {
            defer wg.Done()
            for running {
                status.Print()
                time.Sleep(time.Duration(time.Second/6))
            }
        }()

        status.Label = "Looking for NTP data..."
        log.Infof("Looking for NTP data into pcap file, this can take a while. Please be patient.")
        diff, err := ntpcalc.GetFileDelta(pcapFiles.fromFile)
        if err != nil {
            log.Error("Error getting file time delta", "err", err)
            os.Exit(2)
        }

        //Check if need to auto name output file
        if pcapFiles.toFile == "" {
            n, err := pcapw.NewPcapNamerWithPrefix(pcapFiles.fromFile, "dump")
            if err != nil {
                log.Error("Error setting file name", "err", err)
                os.Exit(2)
            }

            n.TimeDiff = *diff
            pcapFiles.toFile = n.GetNameFromTime()

            pcapFiles.toFile, err = resolver.ResolveFullPath(pcapFiles.toFile)
            if err != nil {
                log.Error("Error setting file name", "err", err)
                os.Exit(2)
            }
            pcapFiles.toExt = strings.ToLower(filepath.Ext(pcapFiles.toFile))

            if pcapFiles.toExt == "" {
                log.Error("Error setting file name", "err", "destination files must have extensions")
                os.Exit(2)
            }

            if !tools.SliceHasStr(pcapExtensions, pcapFiles.toExt) {
                log.Error("Error setting file name", "err", fmt.Sprintf("unsupported to (%s) file type", pcapFiles.toExt))
                os.Exit(2)
            }

            if isv, err := resolver.IsValidAndNotExists(pcapFiles.toFile); !isv {
                log.Error("Error setting file name", "err", err)
                os.Exit(2)
            }

            log.Infof("Converting to %s", pcapFiles.toFile)
        }

        // create reader
        r, err := gopcap.Open(pcapFiles.fromFile)
        if err != nil {
            log.Error("PCAP Open error (handle to read packet):", "err", err)
            os.Exit(2)
        }
        defer r.Close()

        w, err := pcapw.Open(pcapFiles.toFile, r.Header)
        if err != nil {
            log.Error("PCAP Open error (handle to write packet):", "err", err)
            os.Exit(2)
        }
        defer w.Close()

        log.Infof("Adjusting PCAP packages time to %s ahead", tools.FormatDuration(*diff))

        wg.Add(1)
        go func() {
            ascii.HideCursor()
            defer wg.Done()
            defer ascii.ShowCursor()

            status.Label = "Adjusting pcap time ->"
            status.ShowCounter = true

            for {
                h, data, err := r.ReadNextPacket()
                if err != nil {
                    if err == io.EOF {
                        break
                    }
                    log.Error("PCAP read error:", err)
                    return
                }

                status.Packets++

                //Calculate new package time
                newTime := (time.Unix(int64(h.TsSec), int64(h.TsUsec))).Add(*diff)
                h.TsSec = int32(newTime.Unix())                   // seconds since Unix epoch
                h.TsUsec = int32(newTime.UnixNano()/1e3 % 1e6)    // microseconds component

                if err := w.WritePacket(h, data); err != nil {
                    log.Printf("Failed to send packet: %s\n", err)
                    log.Error("PCAP writting error:", err)
                    return
                }

            }
            running = false
            time.Sleep(time.Second)
        }()

        wg.Wait()
        
        fmt.Fprintf(os.Stderr, "%s\n%s\r\033[A", 
            "                                                                                ",
            "                                                                                ",
        )
        ascii.ClearLine()

        ediff := time.Now().Sub(startTime)
        out := time.Time{}.Add(ediff)

        st := "Convertion status\n"
        st += "     -> Elapsed time.......: %s\n"
        st += "     -> Packets converted..: %s\n"

        log.Infof(st, 
            out.Format("15:04:05"),
            tools.FormatIntComma(status.Packets),
        )

    },
}

func init() {
    rootCmd.AddCommand(autoNtpCmd)

    autoNtpCmd.Flags().StringVarP(&pcapFiles.fromFile, "pcap", "i", "", "PCAP source file")
    autoNtpCmd.Flags().StringVarP(&pcapFiles.toFile, "output-file", "o", "", "The file to write adjusted PCAP data to")

    //autoNtpCmd.PersistentFlags().StringVar(&rptFilter, "filter", "", "Comma-separated terms to filter results")
}
