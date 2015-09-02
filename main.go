package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func main() {
	var out string
	var split bool
	var skip, lim int

	flag.StringVar(&out, "out", "-", "Write raw data to `FILE`; \"-\" for stdout")
	flag.BoolVar(&split, "split", false, "Split output into one file per packet")
	flag.IntVar(&skip, "skip", 0, "Skip `N` packets at start of capture")
	flag.IntVar(&lim, "lim", 0, "Limit outout to `N` packets")

	flag.Usage = usage
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}

	var outFile io.WriteCloser
	switch out {
	case "-":
		if split {
			fmt.Println("Cannot split to stdout")
			os.Exit(1)
		}
		outFile = os.Stdout

	case "":
		flag.Usage()
		os.Exit(1)

	default:
		if !split {
			fd, err := os.Create(out)
			fatal(err)
			outFile = fd
		}
	}

	handle, err := pcap.OpenOffline(flag.Arg(0))
	fatal(err)

	i := 0
	w := 0
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for pkt := range packetSource.Packets() {
		if i < skip {
			i++
			continue
		}
		if lim > 0 && w > lim {
			break
		}
		if split {
			if outFile != nil {
				err := outFile.Close()
				fatal(err)
			}

			fd, err := os.Create(fmt.Sprintf("%s-%d", out, i))
			fatal(err)
			outFile = fd
		}
		outFile.Write(pkt.ApplicationLayer().Payload())
		i++
		w++
	}
}

func usage() {
	fmt.Println("Usage of extractudp:")
	fmt.Println("  extractudp [options] <infile>")
	fmt.Println()
	fmt.Println("Options:")
	flag.PrintDefaults()
}

func fatal(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
