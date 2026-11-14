// Package proc keeps a userspace process table so every event can carry
// executable, command line, ancestry and container context.
package proc

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/exedev/warden/internal/event"
)

type Proc struct {
	PID       uint32
	PPID      uint32
	UID       uint32
	Exe       string
	Cmdline   string
	Start     time.Time
	Container string
	exited    time.Time
}

func (p *Proc) Name() string { return filepath.Base(p.Exe) }

type Table struct {
	mu       sync.Mutex
	m        map[uint32]*Proc
	hashes   map[string]string // "path|size|mtime" -> sha256
	cgroups  map[uint64]string // cgroup id (cgroupfs inode) -> container id or ""
	lastScan time.Time
}

func NewTable() *Table {
	t := &Table{m: map[uint32]*Proc{}, hashes: map[string]string{}, cgroups: map[uint64]string{}}
	t.scan()
	go t.gc()
	return t
}

func (t *Table) scan() {
	ents, _ := os.ReadDir("/proc")
	for _, e := range ents {
		pid, err := strconv.ParseUint(e.Name(), 10, 32)
		if err != nil {
			continue
		}
		if p := fromProc(uint32(pid)); p != nil {
			t.m[p.PID] = p
		}
	}
}

func (t *Table) gc() {
	for range time.Tick(30 * time.Second) {
		t.mu.Lock()
		for pid, p := range t.m {
			if !p.exited.IsZero() && time.Since(p.exited) > time.Minute {
				delete(t.m, pid)
			}
		}
		t.mu.Unlock()
	}
}

var containerRe = regexp.MustCompile(`(?:docker[-/]|containerd[-/]|cri-containerd-|crio-|libpod-)([0-9a-f]{12,64})`)

func fromProc(pid uint32) *Proc {
	dir := fmt.Sprintf("/proc/%d", pid)
	p := &Proc{PID: pid}
	p.Exe, _ = os.Readlink(dir + "/exe")
	p.Exe = strings.TrimSuffix(p.Exe, " (deleted)")
	if b, err := os.ReadFile(dir + "/cmdline"); err == nil {
		p.Cmdline = strings.TrimSpace(strings.ReplaceAll(string(b), "\x00", " "))
	}
	f, err := os.Open(dir + "/status")
	if err != nil {
		return nil
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if v, ok := strings.CutPrefix(line, "PPid:"); ok {
			n, _ := strconv.ParseUint(strings.TrimSpace(v), 10, 32)
			p.PPID = uint32(n)
		} else if v, ok := strings.CutPrefix(line, "Uid:"); ok {
			fs := strings.Fields(v)
			if len(fs) > 0 {
				n, _ := strconv.ParseUint(fs[0], 10, 32)
				p.UID = uint32(n)
			}
		} else if p.Exe == "" {
			if v, ok := strings.CutPrefix(line, "Name:"); ok {
				p.Exe = "[" + strings.TrimSpace(v) + "]"
			}
		}
	}
	p.Container = containerOf(pid)
	return p
}

func containerOf(pid uint32) string {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
	if err != nil {
		return ""
	}
	if m := containerRe.FindSubmatch(b); m != nil {
		id := string(m[1])
		if len(id) > 12 {
			id = id[:12]
		}
		return id
	}
	return ""
}

// containerByCgroup maps the kernel's cgroup id (the cgroupfs directory
// inode) to a container id. Unlike /proc/<pid>/cgroup this still works
// after short-lived processes have exited. Caller holds t.mu.
func (t *Table) containerByCgroup(id uint64) string {
	if c, ok := t.cgroups[id]; ok {
		return c
	}
	if time.Since(t.lastScan) < time.Second {
		return ""
	}
	t.lastScan = time.Now()
	filepath.WalkDir("/sys/fs/cgroup", func(p string, d os.DirEntry, err error) error {
		if err != nil || !d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		c := ""
		if m := containerRe.FindStringSubmatch(p); m != nil {
			c = m[1]
			if len(c) > 12 {
				c = c[:12]
			}
		}
		t.cgroups[st.Ino] = c
		return nil
	})
	return t.cgroups[id]
}

func (t *Table) get(pid uint32) *Proc {
	if p, ok := t.m[pid]; ok {
		return p
	}
	if p := fromProc(pid); p != nil {
		t.m[pid] = p
		return p
	}
	return nil
}

// Observe updates the table from e and enriches e with process context.
func (t *Table) Observe(e *event.Event) {
	t.mu.Lock()
	defer t.mu.Unlock()

	switch e.Type {
	case "exec":
		p := &Proc{PID: e.TGID, PPID: e.PPID, UID: e.UID, Start: e.Time}
		p.Exe, _ = os.Readlink(fmt.Sprintf("/proc/%d/exe", e.TGID))
		p.Exe = strings.TrimSuffix(p.Exe, " (deleted)")
		if p.Exe == "" {
			p.Exe = e.Fields["exec.filename"].(string)
		}
		p.Cmdline = e.Fields["exec.args"].(string)
		if old, ok := t.m[e.TGID]; ok && old.Container != "" {
			p.Container = old.Container
		} else {
			p.Container = containerOf(e.TGID)
		}
		t.m[e.TGID] = p
	case "exit":
		if p, ok := t.m[e.TGID]; ok {
			p.exited = e.Time
		}
	}

	p := t.get(e.TGID)
	if p == nil {
		p = &Proc{PID: e.TGID, PPID: e.PPID, Exe: e.Comm}
	}
	if e.PPID == 0 {
		e.PPID = p.PPID
	}
	e.Set("proc.exe", p.Exe)
	e.Set("proc.name", p.Name())
	e.Set("proc.cmdline", p.Cmdline)
	container := p.Container
	if id, ok := e.Fields["cgroup_id"].(uint64); ok && id != 0 {
		if c := t.containerByCgroup(id); c != "" {
			container = c
		}
	}
	e.Set("container", container)

	var names, exes []string
	tree := []string{fmt.Sprintf("%s(%d)", p.Name(), p.PID)}
	cur := e.PPID
	for i := 0; i < 12 && cur > 0; i++ {
		a := t.get(cur)
		if a == nil {
			break
		}
		if i == 0 {
			e.Set("parent.exe", a.Exe)
			e.Set("parent.name", a.Name())
			e.Set("parent.cmdline", a.Cmdline)
		}
		names = append(names, a.Name())
		exes = append(exes, a.Exe)
		tree = append(tree, fmt.Sprintf("%s(%d)", a.Name(), a.PID))
		if a.PPID == cur {
			break
		}
		cur = a.PPID
	}
	e.Set("ancestors.name", names)
	e.Set("ancestors.exe", exes)
	for i, j := 0, len(tree)-1; i < j; i, j = i+1, j-1 {
		tree[i], tree[j] = tree[j], tree[i]
	}
	e.Set("process_tree", strings.Join(tree, " > "))
}

// Hash returns the sha256 of a process's executable, cached by path/size/mtime.
func (t *Table) Hash(pid uint32, path string) string {
	src := fmt.Sprintf("/proc/%d/exe", pid)
	st, err := os.Stat(src)
	if err != nil {
		src = path
		if st, err = os.Stat(src); err != nil {
			return ""
		}
	}
	key := fmt.Sprintf("%s|%d|%d", path, st.Size(), st.ModTime().UnixNano())
	t.mu.Lock()
	h, ok := t.hashes[key]
	t.mu.Unlock()
	if ok {
		return h
	}
	f, err := os.Open(src)
	if err != nil {
		return ""
	}
	defer f.Close()
	d := sha256.New()
	if _, err := io.Copy(d, io.LimitReader(f, 256<<20)); err != nil {
		return ""
	}
	h = hex.EncodeToString(d.Sum(nil))
	t.mu.Lock()
	t.hashes[key] = h
	t.mu.Unlock()
	return h
}
