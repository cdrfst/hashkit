// hashkit:文件哈希计算、清单生成与校验的命令行小工具,支持 MD5 / SHA-256(hash 命令另支持国密 SM3)。
//
// 退出码:0 = 全部一致,1 = 存在不一致,2 = 运行出错。
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"hashkit/hashkit"
)

const usage = `hashkit - 文件哈希计算、清单生成与校验(MD5 / SHA-256,hash 命令另支持 SM3)

用法:
  hashkit hash   <文件或目录>... [-a md5|sm3|sha256|all] [-o 输出文件] [-r]
  hashkit verify <校验文件> [-C 目录] [-a md5|sha256|all]
  hashkit verify <文件> <哈希值> [-a md5|sha256|all]
  hashkit dir    <目录A> <目录B> [-a md5|sha256|all] [-r] [-v]

-a 默认 sha256(verify 默认 all,即按清单或哈希长度自动识别);SM3 仅 hash 命令支持
-r 递归子目录(默认只处理目录第一层文件)

退出码: 0 一致 | 1 不一致 | 2 出错`

type outcome int

const (
	ok outcome = iota
	mismatch
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	out, err := run(os.Args[1], os.Args[2:])
	if err != nil {
		fmt.Fprintln(os.Stderr, "错误:", err)
		os.Exit(2)
	}
	os.Exit(int(out))
}

// parse 允许选项出现在位置参数之前或之后(标准 flag 包遇到首个位置参数即停止)。
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return pos, nil
		}
		pos = append(pos, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// run 按子命令名分发:为该子命令注册选项、解析参数、校验位置参数个数,
// 然后调用对应的 doXxx 函数。返回值决定进程退出码(见 main)。
func run(cmd string, args []string) (outcome, error) {
	// ContinueOnError:解析失败时返回 error,而不是由 flag 包直接退出进程。
	fs := flag.NewFlagSet(cmd, flag.ContinueOnError)
	switch cmd {
	case "hash":
		// 计算哈希并输出清单:-a 默认 sha256,all 为 MD5/SM3/SHA-256 全部(SM3 仅此命令支持);
		// -o 为空时输出到标准输出;目录默认只取第一层文件,-r 递归子目录。
		algo := fs.String("a", "sha256", "算法(md5|sm3|sha256|all)")
		out := fs.String("o", "", "输出文件(默认输出到标准输出)")
		recursive := fs.Bool("r", false, "递归子目录")
		p, err := parse(fs, args)
		if err != nil {
			return ok, err
		}
		return doHash(p, *algo, *out, *recursive)
	case "verify":
		// 校验:1 个位置参数为校验文件(哈希清单),2 个为 <文件> <哈希值>。
		// -a 约束允许的算法,默认 all 即按清单标签或哈希长度自动识别;
		// -C 仅清单模式有效,指定被校验文件所在目录,为空时取校验文件自身所在目录。
		algo := fs.String("a", "all", "允许的算法(md5|sha256|all)")
		dir := fs.String("C", "", "文件所在目录(默认为校验文件所在目录,仅清单模式)")
		p, err := parse(fs, args)
		if err != nil {
			return ok, err
		}
		return doVerify(p, *dir, *algo)
	case "dir":
		// 对比两个目录:默认使用 SHA-256、只比较第一层文件,-r 递归;-v 同时列出内容一致的文件。
		algo := fs.String("a", "sha256", "算法(md5|sha256|all)")
		recursive := fs.Bool("r", false, "递归子目录")
		verbose := fs.Bool("v", false, "同时列出一致的文件")
		p, err := parse(fs, args)
		if err != nil {
			return ok, err
		}
		if len(p) != 2 {
			return ok, errors.New("dir 需要两个目录")
		}
		return doDir(p[0], p[1], *algo, *recursive, *verbose)
	case "-h", "--help", "help":
		// 帮助信息输出到标准输出,按正常结束处理(退出码 0)。
		fmt.Println(usage)
		return ok, nil
	}
	// 未匹配任何子命令:返回错误并附带用法说明,由 main 以退出码 2 退出。
	return ok, fmt.Errorf("未知命令 %q\n\n%s", cmd, usage)
}

func hf(path string, a hashkit.Algo) (string, error) {
	h, err := hashkit.HashFile(path, a)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return h, nil
}

func doVerify(args []string, dir, algo string) (outcome, error) {
	allowed, err := hashkit.ParseCommonAlgo(algo)
	if err != nil {
		return ok, err
	}
	var entries []hashkit.Entry
	var paths []string // 与 entries 一一对应的实际文件路径
	switch len(args) {
	case 1: // 清单模式
		data, err := os.ReadFile(args[0])
		if err != nil {
			return ok, err
		}
		if entries, err = hashkit.ParseChecksumText(string(data)); err != nil {
			return ok, err
		}
		if dir == "" {
			dir = filepath.Dir(args[0])
		}
		for _, e := range entries {
			paths = append(paths, filepath.Join(dir, filepath.FromSlash(e.File)))
		}
	case 2: // 单个文件 + 哈希值,算法由哈希长度确定
		if dir != "" {
			return ok, errors.New("-C 仅用于校验文件模式")
		}
		exp := hashkit.Normalize(args[1])
		al, valid := hashkit.Detect(exp)
		if !valid {
			return ok, fmt.Errorf("无法识别哈希长度 %d(需 32 位 MD5 或 64 位 SHA-256 十六进制)", len(exp))
		}
		entries = []hashkit.Entry{{Hash: exp, Algo: al, File: args[0]}}
		paths = []string{args[0]}
	default:
		return ok, errors.New("verify 需要 <校验文件> 或 <文件> <哈希值>")
	}
	for _, e := range entries {
		if !hashkit.Contains(allowed, e.Algo) {
			return ok, fmt.Errorf("%s: 哈希对应 %s,与 -a 指定的算法不符", e.File, e.Algo)
		}
	}

	var pass, bad, missing int
	for i, e := range entries {
		h, err := hashkit.HashFile(paths[i], e.Algo)
		switch {
		case err != nil:
			missing++
			fmt.Printf("%s: 无法读取 (%v)\n", e.File, err)
		case h == e.Hash:
			pass++
			fmt.Printf("%s: 通过 ✔ [%s]\n", e.File, e.Algo)
		default:
			bad++
			fmt.Printf("%s: 不一致 ✘\n  期望: %s\n  实际 [%s]: %s\n", e.File, e.Hash, e.Algo, h)
		}
	}
	fmt.Printf("\n合计 %d 项:通过 %d,不一致 %d,无法读取 %d\n", len(entries), pass, bad, missing)
	if bad == 0 && missing == 0 {
		return ok, nil
	}
	return mismatch, nil
}

// doHash 计算文件或目录的哈希并输出:单一 MD5/SHA-256 输出 md5sum 风格(可交给 verify 校验),
// SM3 或 all 输出带算法标签的行(`ALGO (文件) = 哈希`)。
func doHash(paths []string, algo, out string, recursive bool) (outcome, error) {
	algos, err := hashkit.ParseAlgo(algo)
	if err != nil {
		return ok, err
	}
	if len(paths) == 0 {
		return ok, errors.New("请至少指定一个文件或目录")
	}
	var per [][]hashkit.Entry // per[k] 为第 k 种算法的结果,文件顺序相同
	skipped := 0
	for _, a := range algos {
		es, sk, err := hashkit.GenerateChecksums(paths, a, recursive, out)
		if err != nil {
			return ok, err
		}
		per, skipped = append(per, es), sk
	}
	if len(per[0]) == 0 {
		return ok, errors.New("没有找到可计算哈希的文件")
	}
	if skipped > 0 {
		fmt.Fprintf(os.Stderr, "提示: 已跳过 %d 个子目录,如需包含请加 -r\n", skipped)
	}
	var text string
	if len(algos) == 1 && algos[0] != hashkit.SM3 {
		text = hashkit.FormatGNU(per[0])
	} else {
		var merged []hashkit.Entry // 按文件分组,同一文件的各算法相邻
		for i := range per[0] {
			for k := range algos {
				merged = append(merged, per[k][i])
			}
		}
		text = hashkit.FormatBSD(merged)
	}
	if out == "" {
		fmt.Print(text)
		return ok, nil
	}
	if err := os.WriteFile(out, []byte(text), 0o644); err != nil {
		return ok, err
	}
	fmt.Printf("已写入 %d 项 -> %s\n", len(per[0]), out)
	return ok, nil
}

func doDir(a, b, algo string, recursive, verbose bool) (outcome, error) {
	algos, err := hashkit.ParseCommonAlgo(algo)
	if err != nil {
		return ok, err
	}
	res := ok
	for i, al := range algos {
		d, err := hashkit.CompareDirs(a, b, al, recursive)
		if err != nil {
			return ok, err
		}
		fmt.Printf("[%s] 一致 %d | 不同 %d | 仅左侧 %d | 仅右侧 %d | 出错 %d\n",
			al, len(d.Same), len(d.Different), len(d.OnlyLeft), len(d.OnlyRight), len(d.Errors))
		if verbose {
			for _, f := range d.Same {
				fmt.Println("  =  " + f)
			}
		}
		for _, f := range d.Different {
			fmt.Println("  ≠  " + f)
		}
		for _, f := range d.OnlyLeft {
			fmt.Printf("  <  %s  (仅 %s)\n", f, a)
		}
		for _, f := range d.OnlyRight {
			fmt.Printf("  >  %s  (仅 %s)\n", f, b)
		}
		errFiles := make([]string, 0, len(d.Errors))
		for f := range d.Errors {
			errFiles = append(errFiles, f)
		}
		sort.Strings(errFiles) // map 遍历无序,排序后输出顺序固定
		for _, f := range errFiles {
			fmt.Printf("  !  %s: %s\n", f, d.Errors[f])
		}
		if !d.Identical() {
			res = mismatch
		}
		if i == 0 && d.Skipped > 0 {
			fmt.Fprintf(os.Stderr, "提示: 已跳过 %d 个子目录,如需包含请加 -r\n", d.Skipped)
		}
	}
	return res, nil
}
