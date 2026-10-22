package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"shadow/internal/ext4"
)

type fileResult struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
	Output string `json:"output,omitempty"`
}

type report struct {
	Image       string          `json:"image"`
	VolumeLabel string          `json:"volume_label,omitempty"`
	BlockSize   uint32          `json:"block_size"`
	Files       []fileResult    `json:"files,omitempty"`
	ExtractAll  *ext4.TreeStats `json:"extract_all,omitempty"`
}

func main() {
	image := flag.String("image", "", "ext4 image file")
	outDir := flag.String("o", "", "output directory (files written at their in-image path)")
	extractAll := flag.String("extract-all", "", "extract the whole tree to this directory")
	flag.Parse()

	if *image == "" || (flag.NArg() == 0 && *extractAll == "") {
		fmt.Fprintln(os.Stderr, "usage: ext4get -image <rootfs.img> [-o <dir>] <in-image path>...\n       ext4get -image <rootfs.img> -extract-all <dir>")
		os.Exit(2)
	}

	fs, err := ext4.Open(*image)
	if err != nil {
		fatal(err)
	}
	defer fs.Close()

	rep := report{Image: *image, VolumeLabel: fs.VolumeLabel(), BlockSize: fs.BlockSize()}

	if *extractAll != "" {
		stats, err := fs.ExtractTree(*extractAll)
		if err != nil {
			fatal(err)
		}
		rep.ExtractAll = &stats
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rep); err != nil {
			fatal(err)
		}
		return
	}

	type payload struct {
		res  fileResult
		data []byte
	}
	payloads := make([]payload, 0, flag.NArg())
	for _, p := range flag.Args() {
		if !strings.HasPrefix(p, "/") {
			fatal(fmt.Errorf("%q: path must be absolute", p))
		}
		clean := filepath.ToSlash(filepath.Clean(p))
		if strings.HasPrefix(clean, "/../") || clean == "/.." {
			fatal(fmt.Errorf("%q: path escapes image root", p))
		}
		data, err := fs.ReadFile(clean)
		if err != nil {
			fatal(err)
		}
		sum := sha256.Sum256(data)
		res := fileResult{Path: clean, Size: int64(len(data)), SHA256: hex.EncodeToString(sum[:])}
		if *outDir != "" {
			out := filepath.Join(*outDir, strings.TrimPrefix(clean, "/"))
			res.Output = out
		}
		payloads = append(payloads, payload{res: res, data: data})
	}

	for _, p := range payloads {
		if p.res.Output != "" {
			if err := os.MkdirAll(filepath.Dir(p.res.Output), 0o755); err != nil {
				fatal(err)
			}
			if err := os.WriteFile(p.res.Output, p.data, 0o644); err != nil {
				fatal(err)
			}
			// Carry the inode's permission bits: a non-executable responder
			// makes qemu-user exit silently, with no error on either stream.
			if _, mode, err := fs.Stat(p.res.Path); err == nil {
				if err := os.Chmod(p.res.Output, os.FileMode(mode&0o777)); err != nil {
					fatal(err)
				}
			}
		}
		rep.Files = append(rep.Files, p.res)
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(rep); err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "ext4get:", err)
	os.Exit(1)
}
