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
	
	"os"
	"fmt"
	"time"
	"os/signal"
    "syscall"

	//"github.com/helviojunior/pcapraptor/internal/tools"
	"github.com/helviojunior/pcapraptor/internal/ascii"
	"github.com/helviojunior/pcapraptor/pkg/log"
	"github.com/spf13/cobra"
)

var (
	opts = &LoggingOptions{}
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

// Logging is log related options
type LoggingOptions struct {
    // Debug display debug level logging
    Debug bool
    // Silence all logging
    Silence bool
}

var startTime time.Time
var rootCmd = &cobra.Command{
	Use:   "pcapraptor",
	Short: "pcapraptor is a modular PCAP file worker",
	Long:  ascii.Logo(),
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {

        startTime = time.Now()

	    if cmd.CalledAs() != "version" {
			fmt.Println(ascii.Logo())
		}

		if opts.Silence {
			log.EnableSilence()
		}

		if opts.Debug && !opts.Silence {
			log.EnableDebug()
			log.Debug("debug logging enabled")
		}

		return nil
	},
}

func Execute() {

	ascii.SetConsoleColors()

	c := make(chan os.Signal)
    signal.Notify(c, os.Interrupt, syscall.SIGTERM)
    go func() {
        <-c
        ascii.ClearLine()
        fmt.Fprintf(os.Stderr, "\r\n")
        ascii.ClearLine()
        ascii.ShowCursor()
        log.Warn("interrupted, shutting down...                            ")
        ascii.ClearLine()
        fmt.Printf("\n")
        os.Exit(2)
    }()

	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.SilenceErrors = true
	err := rootCmd.Execute()
	if err != nil {
		var cmd string
		c, _, cerr := rootCmd.Find(os.Args[1:])
		if cerr == nil {
			cmd = c.Name()
		}

		v := "\n"

		if cmd != "" {
			v += fmt.Sprintf("An error occured running the `%s` command\n", cmd)
		} else {
			v += "An error has occured. "
		}

		v += "The error was:\n\n" + fmt.Sprintf("```%s```", err)
		fmt.Println(ascii.Markdown(v))

		os.Exit(1)
	}

	//Time to wait the logger flush
	time.Sleep(time.Second/4)
    ascii.ShowCursor()
    fmt.Printf("\n")
}

func init() {
	// Disable Certificate Validation (Globally)
	//http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}

	rootCmd.PersistentFlags().BoolVarP(&opts.Debug, "debug-log", "D", false, "Enable debug logging")
	rootCmd.PersistentFlags().BoolVarP(&opts.Silence, "quiet", "q", false, "Silence (almost all) logging")
	
    rootCmd.PersistentFlags().StringVarP(&pcapFiles.fromFile, "pcap", "i", "", "PCAP source file")
}
