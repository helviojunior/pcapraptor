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

package ascii

import (
	"fmt"
	"strings"
	"github.com/helviojunior/pcapraptor/internal/version"
)

// Logo returns the pcapraptor ascii logo
func Logo() string {
	txt := `                   
{B}______  _____   ___  ______ {G}               _             
{B}| ___ \/  __ \ / _ \ | ___ \{G} __ __ _ _ __ | |_ ___  _ __ 
{B}| |_/ /| /  \// /_\ \| |_/ /{G}'__/ _' | '_ \| __/ _ \| '__|
{B}|  __/ | |    |  _  ||  __/{G} | ( |_| | |_) | || (_) | |   
{B}| |    | \__/\| | | || |  {G}|_|  \__,_| .__/ \__\___/|_|   
{B}\_|     \____/\_| |_/\_|  {G}          |_| {O}`
	txt += fmt.Sprintf("Ver: %s-%s\033[0m", version.Version, version.GitHash)
	txt = strings.Replace(txt, "{G}", "\033[32m", -1)
	txt = strings.Replace(txt, "{B}", "\033[36m", -1)
	txt = strings.Replace(txt, "{O}", "\033[33m", -1)
	txt = strings.Replace(txt, "{W}", "\033[0m", -1)
	return fmt.Sprintln(txt)
}

// LogoHelp returns the logo, with help
func LogoHelp(s string) string {
	return fmt.Sprintln(Logo()) + s
}
