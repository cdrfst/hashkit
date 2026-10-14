// Package hashkit 提供 MD5 / SHA-256 文件哈希计算、清单生成与校验、目录对比,以及 hash 命令专用的 SM3 计算。
package hashkit

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	"github.com/emmansun/gmsm/sm3"
)

// Algo 表示哈希算法。
type Algo int

const (
	MD5 Algo = iota
	SM3
	SHA256
)

func (a Algo) String() string {
	switch a {
	case MD5:
		return "MD5"
	case SM3:
		return "SM3"
	default:
		return "SHA256"
	}
}

func (a Algo) newHash() hash.Hash {
	switch a {
	case MD5:
		return md5.New()
	case SM3:
		return sm3.New()
	default:
		return sha256.New()
	}
}

// AllAlgos 返回全部支持的算法。
func AllAlgos() []Algo { return []Algo{MD5, SM3, SHA256} }

// CommonAlgos 返回除 hash 命令外其它命令支持的算法(不含 SM3)。
func CommonAlgos() []Algo { return []Algo{MD5, SHA256} }

// ParseCommonAlgo 解析除 hash 命令外其它命令的算法名;"all" 返回 MD5 与 SHA-256,SM3 仅 hash 命令支持。
func ParseCommonAlgo(s string) ([]Algo, error) {
	switch strings.ToLower(s) {
	case "sm3":
		return nil, errors.New("SM3 仅 hash 命令支持")
	case "all":
		return CommonAlgos(), nil
	}
	a, err := ParseAlgo(s)
	if err != nil {
		return nil, fmt.Errorf("未知算法 %q(可选 md5|sha256|all)", s)
	}
	return a, nil
}

// ParseAlgo 解析 hash 命令的算法名;"all" 返回全部(含 SM3)。
func ParseAlgo(s string) ([]Algo, error) {
	switch strings.ToLower(s) {
	case "md5":
		return []Algo{MD5}, nil
	case "sm3":
		return []Algo{SM3}, nil
	case "sha256", "sha-256":
		return []Algo{SHA256}, nil
	case "all":
		return AllAlgos(), nil
	}
	return nil, fmt.Errorf("未知算法 %q(可选 md5|sm3|sha256|all)", s)
}

// Detect 按十六进制串长度给出算法:32 -> MD5;64 -> SHA-256(SM3 不参与识别,仅 hash 命令支持)。
func Detect(h string) (Algo, bool) {
	if _, err := hex.DecodeString(h); err != nil {
		return 0, false
	}
	switch len(h) {
	case 32:
		return MD5, true
	case 64:
		return SHA256, true
	}
	return 0, false
}

// Contains 判断候选列表是否包含 a。
func Contains(list []Algo, a Algo) bool {
	for _, x := range list {
		if x == a {
			return true
		}
	}
	return false
}

// Normalize 去空白并转小写。
func Normalize(h string) string { return strings.ToLower(strings.TrimSpace(h)) }

// HashReader 流式计算哈希(小写十六进制)。
func HashReader(r io.Reader, a Algo) (string, error) {
	h := a.newHash()
	if _, err := io.CopyBuffer(h, r, make([]byte, 1<<20)); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// HashFile 计算文件哈希。
func HashFile(path string, a Algo) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	return HashReader(f, a)
}

// ---------------------------------------------------------------- 校验文件

// Entry 是校验文件中的一条记录。
type Entry struct {
	Hash string
	Algo Algo
	File string
}

// ParseChecksumText 解析 md5sum 风格(`hash  file` / `hash *file`)与 BSD 风格(`MD5 (file) = hash`)。
func ParseChecksumText(text string) ([]Entry, error) {
	var out []Entry
	for i, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.TrimPrefix(raw, "\xef\xbb\xbf"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		e, ok := parseBSD(line)
		if !ok {
			e, ok = parseGNU(line)
		}
		if !ok {
			return nil, fmt.Errorf("第 %d 行无法解析: %s", i+1, raw)
		}
		out = append(out, e)
	}
	return out, nil
}

func parseBSD(line string) (Entry, bool) {
	idx := strings.LastIndex(line, " = ")
	if idx < 0 {
		return Entry{}, false
	}
	left, h := line[:idx], Normalize(line[idx+3:])
	p := strings.Index(left, " (")
	if p < 0 || !strings.HasSuffix(left, ")") {
		return Entry{}, false
	}
	tag, file := left[:p], left[p+2:len(left)-1]
	algos, err := ParseCommonAlgo(tag)
	if d, valid := Detect(h); err != nil || len(algos) != 1 || strings.EqualFold(tag, "all") || !valid || d != algos[0] {
		return Entry{}, false
	}
	return Entry{Hash: h, Algo: algos[0], File: file}, true
}

func parseGNU(line string) (Entry, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return Entry{}, false
	}
	h := Normalize(fields[0])
	algo, valid := Detect(h)
	if !valid {
		return Entry{}, false
	}
	file := strings.TrimLeft(line[len(fields[0]):], " \t")
	file = strings.TrimPrefix(file, "*")
	if file == "" {
		return Entry{}, false
	}
	return Entry{Hash: h, Algo: algo, File: file}, true
}

// ---------------------------------------------------------------- 生成清单

// GenerateChecksums 为文件或目录生成哈希条目,按清单路径排序。
// 目录参数默认只取第一层普通文件(跳过的子目录数通过第二个返回值给出),recursive 为 true 时递归;
// 文件参数的清单路径为文件名。exclude 非空时跳过该文件(用于 -o 落在被扫描目录内的情况)。
func GenerateChecksums(paths []string, a Algo, recursive bool, exclude string) ([]Entry, int, error) {
	var excl os.FileInfo
	if exclude != "" {
		excl, _ = os.Stat(exclude) // 尚不存在则无需排除
	}
	files := map[string]string{} // 清单路径 -> 实际路径
	skipped := 0
	add := func(name, real string) error {
		if strings.ContainsAny(name, "\r\n") {
			return fmt.Errorf("文件名含换行符,无法写入清单: %q", name)
		}
		if excl != nil {
			if fi, err := os.Stat(real); err == nil && os.SameFile(fi, excl) {
				return nil
			}
		}
		if prev, dup := files[name]; dup {
			return fmt.Errorf("清单路径重复 %q: %s 与 %s", name, prev, real)
		}
		files[name] = real
		return nil
	}
	for _, p := range paths {
		fi, err := os.Stat(p)
		if err != nil {
			return nil, 0, err
		}
		switch {
		case !fi.IsDir():
			if !fi.Mode().IsRegular() {
				return nil, 0, fmt.Errorf("%s: 不是普通文件", p)
			}
			if err := add(filepath.Base(p), p); err != nil {
				return nil, 0, err
			}
		default:
			m, sk, err := listFiles(p, recursive)
			if err != nil {
				return nil, 0, err
			}
			skipped += sk
			for rel, real := range m {
				if err := add(rel, real); err != nil {
					return nil, 0, err
				}
			}
		}
	}

	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)

	out := make([]Entry, len(names))
	errs := make([]error, len(names))
	jobs := make(chan int)
	var wg sync.WaitGroup
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				h, err := HashFile(files[names[i]], a)
				out[i], errs[i] = Entry{Hash: h, Algo: a, File: names[i]}, err
			}
		}()
	}
	for i := range names {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	for _, err := range errs {
		if err != nil {
			return nil, 0, err
		}
	}
	return out, skipped, nil
}

// FormatGNU 输出 md5sum 风格清单(`hash  file`,LF 换行),可被 ParseChecksumText 解析。
func FormatGNU(entries []Entry) string {
	var b strings.Builder
	for _, e := range entries {
		b.WriteString(e.Hash + "  " + e.File + "\n")
	}
	return b.String()
}

// FormatBSD 输出带算法标签的清单(`MD5 (file) = hash`),用于 SM3 或多算法输出;
// 其中 MD5/SHA256 行可被 ParseChecksumText 解析,SM3 行仅供查看。
func FormatBSD(entries []Entry) string {
	var b strings.Builder
	for _, e := range entries {
		fmt.Fprintf(&b, "%s (%s) = %s\n", e.Algo, e.File, e.Hash)
	}
	return b.String()
}

// ---------------------------------------------------------------- 目录对比

// DirDiff 是目录对比结果,键为相对路径(统一使用 "/")。
type DirDiff struct {
	Same, Different, OnlyLeft, OnlyRight []string
	Errors                               map[string]string
	Skipped                              int // 非递归时跳过的子目录数
}

// Identical 表示两个目录完全一致。
func (d *DirDiff) Identical() bool {
	return len(d.Different) == 0 && len(d.OnlyLeft) == 0 && len(d.OnlyRight) == 0 && len(d.Errors) == 0
}

// listFiles 枚举目录下的普通文件,返回 相对路径(用 "/")-> 实际路径。
// recursive 为 false 时只取第一层,并返回被跳过的子目录数。
func listFiles(root string, recursive bool) (map[string]string, int, error) {
	m := map[string]string{}
	if !recursive {
		ents, err := os.ReadDir(root)
		if err != nil {
			return nil, 0, err
		}
		skipped := 0
		for _, e := range ents {
			switch {
			case e.IsDir():
				skipped++
			case e.Type().IsRegular():
				m[e.Name()] = filepath.Join(root, e.Name())
			}
		}
		return m, skipped, nil
	}
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			m[filepath.ToSlash(rel)] = p
		}
		return nil
	})
	return m, 0, err
}

// CompareDirs 对比两个目录,按相对路径配对,并发计算哈希;recursive 为 false 时只比较第一层文件。
func CompareDirs(left, right string, a Algo, recursive bool) (*DirDiff, error) {
	l, skl, err := listFiles(left, recursive)
	if err != nil {
		return nil, err
	}
	r, skr, err := listFiles(right, recursive)
	if err != nil {
		return nil, err
	}
	d := &DirDiff{Errors: map[string]string{}, Skipped: skl + skr}
	var both []string
	for rel := range l {
		if _, ok := r[rel]; ok {
			both = append(both, rel)
		} else {
			d.OnlyLeft = append(d.OnlyLeft, rel)
		}
	}
	for rel := range r {
		if _, ok := l[rel]; !ok {
			d.OnlyRight = append(d.OnlyRight, rel)
		}
	}

	type result struct {
		rel  string
		same bool
		err  error
	}
	jobs := make(chan string)
	results := make(chan result)
	var wg sync.WaitGroup
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for rel := range jobs {
				ha, err := HashFile(l[rel], a)
				if err == nil {
					var hb string
					if hb, err = HashFile(r[rel], a); err == nil {
						results <- result{rel, ha == hb, nil}
						continue
					}
				}
				results <- result{rel, false, err}
			}
		}()
	}
	go func() {
		for _, rel := range both {
			jobs <- rel
		}
		close(jobs)
		wg.Wait()
		close(results)
	}()
	for res := range results {
		switch {
		case res.err != nil:
			d.Errors[res.rel] = res.err.Error()
		case res.same:
			d.Same = append(d.Same, res.rel)
		default:
			d.Different = append(d.Different, res.rel)
		}
	}
	for _, s := range [][]string{d.Same, d.Different, d.OnlyLeft, d.OnlyRight} {
		sort.Strings(s)
	}
	return d, nil
}
