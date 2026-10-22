package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"shadow/internal/elfscan"
)

func main() {
	elfPath := flag.String("elf", "", "path to the tizen-mtp ELF")
	out := flag.String("o", "", "write JSON to this file instead of stdout")
	flag.Parse()

	if *elfPath == "" {
		fmt.Fprintln(os.Stderr, "usage: elfscan -elf <tizen-mtp> [-o out.json]")
		os.Exit(2)
	}

	res, err := elfscan.Scan(*elfPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "elfscan:", err)
		os.Exit(1)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if *out != "" {
		f, err := os.Create(*out)
		if err != nil {
			fmt.Fprintln(os.Stderr, "elfscan:", err)
			os.Exit(1)
		}
		defer f.Close()
		enc = json.NewEncoder(f)
		enc.SetIndent("", "  ")
	}
	if err := enc.Encode(res); err != nil {
		fmt.Fprintln(os.Stderr, "elfscan:", err)
		os.Exit(1)
	}
}
