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
    "fmt"

    "github.com/helviojunior/pcapraptor/internal/ascii"
    "github.com/helviojunior/pcapraptor/internal/version"
    "github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
    Use:   "version",
    Short: "Get the pcapraptor version",
    Long:  ascii.LogoHelp(`Get the pcapraptor version.`),
    Run: func(cmd *cobra.Command, args []string) {
        fmt.Println(ascii.Logo())

        fmt.Println("Author: Helvio Junior (m4v3r1ck)")
        fmt.Println("Source: https://github.com/helviojunior/pcapraptor")
        fmt.Printf("Version: %s\nGit hash: %s\nBuild env: %s\nBuild time: %s\n\n",
            version.Version, version.GitHash, version.GoBuildEnv, version.GoBuildTime)
    },
}

func init() {
    rootCmd.AddCommand(versionCmd)
}