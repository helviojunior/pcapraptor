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

    "github.com/helviojunior/pcapraptor/pkg/pcapw"
    "github.com/helviojunior/pcapraptor/internal/ascii"
    "github.com/helviojunior/pcapraptor/internal/tools"
    "github.com/helviojunior/pcapraptor/pkg/log"
    "github.com/helviojunior/pcapraptor/pkg/gopcap"
    "github.com/helviojunior/pcapraptor/pkg/netcalc"
    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"

    resolver "github.com/helviojunior/gopathresolver"
    "github.com/spf13/cobra"
)

var privateOnly = false

var locateSubnetCmd = &cobra.Command{
    Use:   "subnets",
    Short: "Look for NTP request/response into PCAP file and calculate package time shifiting",
    Long: ascii.LogoHelp(ascii.Markdown(`
# locate subnets

Enumerate all subnets found at PCAP file.

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

        // create reader
        r, err := gopcap.Open(pcapFiles.fromFile)
        if err != nil {
            log.Error("PCAP Open error (handle to read packet):", "err", err)
            os.Exit(2)
        }
        defer r.Close()

        var w *pcapw.Writer
        if pcapFiles.toFile != "" {
            var err error
            w, err = pcapw.Open(pcapFiles.toFile, r.Header)
            if err != nil {
                log.Error("PCAP Open error (handle to write packet):", "err", err)
                os.Exit(2)
            }
            defer w.Close()
        }

        if privateOnly {
            log.Warn("Checking only private subnets")
        }

        log.Warn("Reading PCAP file...")
        subnetList := []string{}
        hasNoPrivate := false

        wg.Add(1)
        go func() {
            ascii.HideCursor()
            defer wg.Done()
            defer ascii.ShowCursor()

            status.Label = "Getting subnets ->"
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

                packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
                subnet := netcalc.GetSubnetsFromPacket(packet)
                if subnet != nil {
                    if subnet.SrcNet != "" && (!privateOnly || subnet.SrcIsPrivate) {
                        hasNoPrivate = !subnet.SrcIsPrivate || hasNoPrivate
                        n := fmt.Sprintf("%s/%d", subnet.SrcNet, subnet.SrcMask)
                        if !tools.SliceHasStr(subnetList, n) {
                            subnetList = append(subnetList, n)
                            log.Info("Subnet found", "subnet", subnet.SrcNet, "netmask", subnet.SrcMask)
                        }
                    }
                    if subnet.DstNet != "" && subnet.DstNet != subnet.SrcNet && (!privateOnly || subnet.DstIsPrivate)  {
                        hasNoPrivate = !subnet.DstIsPrivate || hasNoPrivate
                        n := fmt.Sprintf("%s/%d", subnet.DstNet, subnet.DstMask)
                        if !tools.SliceHasStr(subnetList, n) {
                            subnetList = append(subnetList, n)
                            log.Info("Subnet found", "subnet", subnet.DstNet, "netmask", subnet.DstMask)
                        }
                    }

                    if w != nil {
                        if err := w.WritePacket(h, data); err != nil {
                            log.Printf("Failed to send packet: %s\n", err)
                            log.Error("PCAP writting error:", err)
                            return
                        }
                    }
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

        log.Warn("Calucating supernets...")
        netGroups := netcalc.GroupSubnets(subnetList)
        for i, group := range netGroups {
            supnet := netcalc.CalculateSupernet(group)
            log.Infof("Supernet %04d: %s (from %d subnets)", i+1, supnet.String(), len(group))
        }

        if hasNoPrivate {
            log.Warn("Public network found. Use the --private-only flag to list and calculate only private networks.")
        }

        ediff := time.Now().Sub(startTime)
        out := time.Time{}.Add(ediff)

        st := "Locate status\n"
        st += "     -> Elapsed time.......: %s\n"
        st += "     -> Packets analysed..: %s\n"

        log.Infof(st, 
            out.Format("15:04:05"),
            tools.FormatIntComma(status.Packets),
        )

    },
}

func init() {
    locateRootCmd.AddCommand(locateSubnetCmd)

    locateSubnetCmd.Flags().StringVarP(&pcapFiles.toFile, "output-file", "o", "", "The file to write adjusted PCAP data to")

    locateSubnetCmd.Flags().BoolVarP(&privateOnly, "private-only", "P", false, "Check just private subnets (192.168.0.0/16, 10.0.0.0/8 and 172.31.0.0/12)")

    //autoNtpCmd.PersistentFlags().StringVar(&rptFilter, "filter", "", "Comma-separated terms to filter results")
}
