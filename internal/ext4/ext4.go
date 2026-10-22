package ext4

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	sbOffset               = 1024
	sbSize                 = 1024
	extMagic               = 0xEF53
	rootInode              = 2
	maxSymlinks            = 40
	featIncompatExtents    = 0x40
	featIncompat64Bit      = 0x80
	featIncompatMetaBG     = 0x10
	featIncompatFlexBG     = 0x200
	featIncompatMmp        = 0x100
	featIncompatBigalloc   = 0x20000
	featIncompatInlineData = 0x8000
	featIncompatEncrypt    = 0x10000
	featIncompatEAInode    = 0x400
	featIncompatFiletype   = 0x2
	featIncompatRecover    = 0x4
	featIncompatJournalDev = 0x8
	featIncompatLargedir   = 0x4000
	featIncompatDirdata    = 0x1000
	featIncompatCsumSeed   = 0x2000

	modeTypeMask = 0xF000
	modeDir      = 0x4000
	modeReg      = 0x8000
	modeLnk      = 0xA000

	roCompatLargeFile = 0x2
	roCompatHugeFile  = 0x8
)

var le = binary.LittleEndian

type FS struct {
	file             *os.File
	blockSize        uint32
	blocksPerGroup   uint32
	inodesPerGroup   uint32
	inodeSize        uint32
	descSize         uint32
	firstDataBlock   uint32
	inodesCount      uint32
	gdtOffset        int64
	featuresIncompat uint32
	featuresRO       uint32
	volumeLabel      string
}

func Open(path string) (*FS, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	sb := make([]byte, sbSize)
	if _, err := f.ReadAt(sb, sbOffset); err != nil {
		f.Close()
		return nil, fmt.Errorf("read superblock: %w", err)
	}
	if le.Uint16(sb[0x38:]) != extMagic {
		f.Close()
		return nil, fmt.Errorf("%s: not an ext2/3/4 filesystem (magic %#x)", path, le.Uint16(sb[0x38:]))
	}
	fs := &FS{file: f}
	fs.inodesCount = le.Uint32(sb[0x00:])
	fs.firstDataBlock = le.Uint32(sb[0x14:])
	logBlockSize := le.Uint32(sb[0x18:])
	fs.blocksPerGroup = le.Uint32(sb[0x20:])
	fs.inodesPerGroup = le.Uint32(sb[0x28:])
	inodeSize := uint32(le.Uint16(sb[0x58:]))
	rev := le.Uint32(sb[0x4C:])
	fs.featuresIncompat = le.Uint32(sb[0x60:])
	fs.featuresRO = le.Uint32(sb[0x64:])

	if logBlockSize > 6 {
		f.Close()
		return nil, fmt.Errorf("unsupported log block size %d", logBlockSize)
	}
	fs.blockSize = 1024 << logBlockSize
	if fs.blocksPerGroup == 0 || fs.inodesPerGroup == 0 {
		f.Close()
		return nil, errors.New("invalid superblock: zero blocks/inodes per group")
	}
	fs.inodeSize = 128
	if rev >= 1 && inodeSize != 0 {
		fs.inodeSize = inodeSize
	}
	if fs.inodeSize > 1024 || fs.inodeSize%4 != 0 {
		f.Close()
		return nil, fmt.Errorf("unsupported inode size %d", fs.inodeSize)
	}
	fs.descSize = 32
	if fs.featuresIncompat&featIncompat64Bit != 0 {
		if ds := uint32(le.Uint16(sb[0xFE:])); ds > 32 {
			fs.descSize = ds
		}
	}

	allowed := uint32(featIncompatFiletype | featIncompatRecover | featIncompat64Bit | featIncompatFlexBG | featIncompatMmp | featIncompatEAInode)
	if fs.featuresIncompat&featIncompatExtents != 0 {
		f.Close()
		return nil, errors.New("extent-based filesystem not supported by this reader (incompat EXTENTS set)")
	}
	if fs.featuresIncompat&featIncompatMetaBG != 0 {
		f.Close()
		return nil, errors.New("meta_bg group descriptor layout not supported")
	}
	unsupported := fs.featuresIncompat &^ allowed
	if unsupported != 0 {
		f.Close()
		return nil, fmt.Errorf("unsupported incompat features %#x", unsupported)
	}

	fs.gdtOffset = int64(fs.blockSize) * int64(fs.firstDataBlock+1)
	label := sb[0x78:0x88]
	fs.volumeLabel = strings.TrimRight(string(label), "\x00")
	return fs, nil
}

func (fs *FS) Close() error { return fs.file.Close() }

func (fs *FS) BlockSize() uint32 { return fs.blockSize }

func (fs *FS) VolumeLabel() string { return fs.volumeLabel }

func (fs *FS) groupDescriptor(group uint32) ([]byte, error) {
	off := fs.gdtOffset + int64(group)*int64(fs.descSize)
	buf := make([]byte, fs.descSize)
	if _, err := fs.file.ReadAt(buf, off); err != nil {
		return nil, fmt.Errorf("read group descriptor %d: %w", group, err)
	}
	return buf, nil
}

func (fs *FS) inodeTableBlock(group uint32) (uint64, error) {
	gd, err := fs.groupDescriptor(group)
	if err != nil {
		return 0, err
	}
	lo := uint64(le.Uint32(gd[0x08:]))
	if fs.descSize >= 64 {
		hi := uint64(le.Uint32(gd[0x28:]))
		lo |= hi << 32
	}
	return lo, nil
}

func (fs *FS) inode(inum uint32) ([]byte, error) {
	if inum == 0 || inum > fs.inodesCount {
		return nil, fmt.Errorf("inode %d out of range (count %d)", inum, fs.inodesCount)
	}
	idx := inum - 1
	group := idx / fs.inodesPerGroup
	index := idx % fs.inodesPerGroup
	table, err := fs.inodeTableBlock(group)
	if err != nil {
		return nil, err
	}
	off := int64(table)*int64(fs.blockSize) + int64(index)*int64(fs.inodeSize)
	buf := make([]byte, fs.inodeSize)
	if _, err := fs.file.ReadAt(buf, off); err != nil {
		return nil, fmt.Errorf("read inode %d: %w", inum, err)
	}
	return buf, nil
}

func (fs *FS) InodeSize(size []byte) int64 {
	n := int64(le.Uint32(size[4:]))
	largeFile := fs.featuresRO&(roCompatLargeFile|roCompatHugeFile) != 0
	ext4ish := fs.featuresIncompat&(featIncompatExtents|featIncompat64Bit) != 0
	if fs.inodeSize >= 128 && (largeFile || ext4ish) {
		n |= int64(le.Uint32(size[108:])) << 32
	}
	return n
}

func (fs *FS) Mode(inode []byte) uint32 { return uint32(le.Uint16(inode[0:])) }

func (fs *FS) readBlockPointers(block uint32, depth int, fn func(uint32) error) error {
	if block == 0 {
		return nil
	}
	if depth == 0 {
		return fn(block)
	}
	data := make([]byte, fs.blockSize)
	if _, err := fs.file.ReadAt(data, int64(block)*int64(fs.blockSize)); err != nil {
		return fmt.Errorf("read indirect block %d: %w", block, err)
	}
	n := int(fs.blockSize) / 4
	for i := 0; i < n; i++ {
		if err := fs.readBlockPointers(le.Uint32(data[i*4:]), depth-1, fn); err != nil {
			return err
		}
	}
	return nil
}

func (fs *FS) blockList(inode []byte, size int64) ([]uint32, error) {
	blocks := make([]uint32, 0, size/int64(fs.blockSize)+1)
	need := func() int64 { return int64(len(blocks)) * int64(fs.blockSize) }
	ptrs := inode[0x28 : 0x28+60]
	for i := 0; i < 12 && need() < size; i++ {
		b := le.Uint32(ptrs[i*4:])
		blocks = append(blocks, b)
	}
	levels := [3]int{1, 2, 3}
	for li, depth := range levels {
		if need() >= size {
			break
		}
		ptr := le.Uint32(ptrs[(12+li)*4:])
		if ptr == 0 {
			for need() < size {
				blocks = append(blocks, 0)
			}
			break
		}
		if err := fs.readBlockPointers(ptr, depth, func(b uint32) error {
			if need() < size {
				blocks = append(blocks, b)
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return blocks, nil
}

func (fs *FS) readFileData(inode []byte, size int64) ([]byte, error) {
	if size < 0 {
		return nil, fmt.Errorf("negative file size %d", size)
	}
	blocks, err := fs.blockList(inode, size)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, size)
	buf := make([]byte, fs.blockSize)
	for _, b := range blocks {
		if int64(len(out)) >= size {
			break
		}
		if b == 0 {
			zeros := make([]byte, fs.blockSize)
			out = append(out, zeros...)
			continue
		}
		if _, err := fs.file.ReadAt(buf, int64(b)*int64(fs.blockSize)); err != nil {
			return nil, fmt.Errorf("read block %d: %w", b, err)
		}
		out = append(out, buf...)
	}
	if int64(len(out)) < size {
		return nil, fmt.Errorf("short file: have %d bytes, inode says %d", len(out), size)
	}
	return out[:size], nil
}

func (fs *FS) readSymlink(inode []byte, size int64) (string, error) {
	if size < 60 {
		return string(inode[0x28 : 0x28+size]), nil
	}
	data, err := fs.readFileData(inode, size)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(data), "\x00"), nil
}

func splitPath(p string) []string {
	var out []string
	for _, c := range strings.Split(p, "/") {
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

type DirEntry struct {
	Name  string
	Inode uint32
}

func (fs *FS) readDirEntries(inode []byte, what string) ([]DirEntry, error) {
	data, err := fs.readFileData(inode, fs.InodeSize(inode))
	if err != nil {
		return nil, err
	}
	var entries []DirEntry
	for off := 0; off+8 <= len(data); {
		inum := le.Uint32(data[off:])
		recLen := int(le.Uint16(data[off+4:]))
		nameLen := int(data[off+6])
		if recLen < 8 || off+recLen > len(data) {
			return nil, fmt.Errorf("corrupt directory entry in %s at %d (rec_len %d)", what, off, recLen)
		}
		if inum != 0 && nameLen > 0 && off+8+nameLen <= len(data) {
			name := string(data[off+8 : off+8+nameLen])
			if name != "." && name != ".." {
				entries = append(entries, DirEntry{Name: name, Inode: inum})
			}
		}
		off += recLen
	}
	return entries, nil
}

func (fs *FS) lookup(dirInum uint32, name string) (uint32, error) {
	inode, err := fs.inode(dirInum)
	if err != nil {
		return 0, err
	}
	if fs.Mode(inode)&modeTypeMask != modeDir {
		return 0, fmt.Errorf("inode %d is not a directory", dirInum)
	}
	entries, err := fs.readDirEntries(inode, fmt.Sprintf("inode %d", dirInum))
	if err != nil {
		return 0, err
	}
	for _, e := range entries {
		if e.Name == name {
			return e.Inode, nil
		}
	}
	return 0, fmt.Errorf("%q not found in directory inode %d", name, dirInum)
}

func (fs *FS) Resolve(path string) (uint32, error) {
	if !strings.HasPrefix(path, "/") {
		return 0, fmt.Errorf("%q: path must be absolute", path)
	}
	cur := uint32(rootInode)
	dirStack := []uint32{rootInode}
	queue := splitPath(path)
	links := 0
	for len(queue) > 0 {
		name := queue[0]
		queue = queue[1:]
		switch name {
		case ".":
			continue
		case "..":
			if len(dirStack) > 1 {
				dirStack = dirStack[:len(dirStack)-1]
			}
			cur = dirStack[len(dirStack)-1]
			continue
		}
		next, err := fs.lookup(cur, name)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", path, err)
		}
		inode, err := fs.inode(next)
		if err != nil {
			return 0, fmt.Errorf("%s: %w", path, err)
		}
		mode := fs.Mode(inode) & modeTypeMask
		if mode == modeLnk {
			links++
			if links > maxSymlinks {
				return 0, fmt.Errorf("%s: too many levels of symbolic links", path)
			}
			target, err := fs.readSymlink(inode, fs.InodeSize(inode))
			if err != nil {
				return 0, fmt.Errorf("%s: %w", path, err)
			}
			tcomps := splitPath(target)
			if strings.HasPrefix(target, "/") {
				dirStack = dirStack[:1]
				cur = rootInode
			}
			queue = append(tcomps, queue...)
			continue
		}
		if mode == modeDir {
			dirStack = append(dirStack, next)
		} else if len(queue) > 0 {
			return 0, fmt.Errorf("%s: %q is not a directory", path, name)
		}
		cur = next
	}
	return cur, nil
}

func (fs *FS) Stat(path string) (size int64, mode uint32, err error) {
	inum, err := fs.Resolve(path)
	if err != nil {
		return 0, 0, err
	}
	inode, err := fs.inode(inum)
	if err != nil {
		return 0, 0, err
	}
	return fs.InodeSize(inode), fs.Mode(inode), nil
}

func (fs *FS) ReadFile(path string) ([]byte, error) {
	inum, err := fs.Resolve(path)
	if err != nil {
		return nil, err
	}
	inode, err := fs.inode(inum)
	if err != nil {
		return nil, err
	}
	mode := fs.Mode(inode) & modeTypeMask
	if mode == modeLnk {
		target, err := fs.readSymlink(inode, fs.InodeSize(inode))
		if err != nil {
			return nil, err
		}
		return fs.ReadFile(target)
	}
	if mode != modeReg {
		return nil, fmt.Errorf("%s: not a regular file (mode %#o)", path, fs.Mode(inode))
	}
	return fs.readFileData(inode, fs.InodeSize(inode))
}

func (fs *FS) ReadDir(path string) ([]DirEntry, error) {
	inum, err := fs.Resolve(path)
	if err != nil {
		return nil, err
	}
	inode, err := fs.inode(inum)
	if err != nil {
		return nil, err
	}
	if fs.Mode(inode)&modeTypeMask != modeDir {
		return nil, fmt.Errorf("%s: not a directory", path)
	}
	return fs.readDirEntries(inode, path)
}

func (fs *FS) ListDir(path string) ([]string, error) {
	entries, err := fs.ReadDir(path)
	if err != nil {
		return nil, err
	}
	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.Name
	}
	return names, nil
}

type TreeStats struct {
	Files    int64 `json:"files"`
	Dirs     int64 `json:"dirs"`
	Symlinks int64 `json:"symlinks"`
	Specials int64 `json:"specials"`
	Bytes    int64 `json:"bytes"`
}

func (fs *FS) ExtractTree(dest string) (TreeStats, error) {
	var stats TreeStats
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return stats, err
	}
	var walk func(dirInum uint32, rel string) error
	walk = func(dirInum uint32, rel string) error {
		inode, err := fs.inode(dirInum)
		if err != nil {
			return err
		}
		entries, err := fs.readDirEntries(inode, rel)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if strings.ContainsAny(e.Name, "/\x00") || e.Name == ".." {
				return fmt.Errorf("unsafe directory entry name %q in %s", e.Name, rel)
			}
			child, err := fs.inode(e.Inode)
			if err != nil {
				return err
			}
			childRel := filepath.Join(rel, e.Name)
			childPath := filepath.Join(dest, childRel)
			mode := fs.Mode(child)
			switch mode & modeTypeMask {
			case modeDir:
				if err := os.MkdirAll(childPath, 0o700); err != nil {
					return err
				}
				stats.Dirs++
				if err := walk(e.Inode, childRel); err != nil {
					return err
				}
				if err := os.Chmod(childPath, os.FileMode(mode&0o777)); err != nil {
					return err
				}
			case modeReg:
				data, err := fs.readFileData(child, fs.InodeSize(child))
				if err != nil {
					return fmt.Errorf("%s: %w", childRel, err)
				}
				if err := os.MkdirAll(filepath.Dir(childPath), 0o700); err != nil {
					return err
				}
				if err := os.WriteFile(childPath, data, os.FileMode(mode&0o777)); err != nil {
					return err
				}
				stats.Files++
				stats.Bytes += int64(len(data))
			case modeLnk:
				target, err := fs.readSymlink(child, fs.InodeSize(child))
				if err != nil {
					return fmt.Errorf("%s: %w", childRel, err)
				}
				if err := os.MkdirAll(filepath.Dir(childPath), 0o700); err != nil {
					return err
				}
				if err := os.Symlink(target, childPath); err != nil {
					return err
				}
				stats.Symlinks++
			default:
				stats.Specials++
			}
		}
		return nil
	}
	if err := walk(rootInode, "."); err != nil {
		return stats, err
	}
	return stats, nil
}
