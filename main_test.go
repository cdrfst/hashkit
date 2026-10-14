package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func code(t *testing.T, cmd string, args ...string) int {
	t.Helper()
	o, err := run(cmd, args)
	if err != nil {
		return 2
	}
	return int(o)
}

func TestCLI(t *testing.T) {
	p := t.TempDir()
	w := func(n, s string) string {
		f := filepath.Join(p, n)
		os.WriteFile(f, []byte(s), 0o644)
		return f
	}
	a, b, c := w("a.txt", "abc"), w("b.txt", "abc"), w("c.txt", "abd")
	const sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	const md5 = "900150983cd24fb0d6963f7d28e17f72"
	const sm3 = "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"
	checks := []struct {
		want int
		cmd  string
		args []string
	}{
		{0, "verify", []string{a, md5}},
		{0, "verify", []string{a, "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"}},
		{0, "verify", []string{a, sha}},
		{0, "verify", []string{b, sha}},
		{1, "verify", []string{c, sha}},
		{1, "verify", []string{c, md5}},
		{1, "verify", []string{a, sm3}},                 // 64 位一律按 SHA-256 比对,SM3 值不一致
		{0, "verify", []string{a, sha, "-a", "sha256"}}, // -a 约束与哈希长度相符
		{0, "verify", []string{a, md5, "-a", "all"}},
		{2, "verify", []string{a, md5, "-a", "sha256"}}, // 哈希是 MD5,与 -a 不符
		{2, "verify", []string{a, sha, "-a", "sm3"}},    // SM3 仅 hash 命令支持
		{2, "verify", []string{a, sha, "-C", p}},        // -C 仅清单模式
		{2, "verify", []string{a, "zz"}},
		{2, "verify", nil},
		{2, "verify", []string{a, b, c}},
		{0, "hash", []string{a}},
		{0, "hash", []string{a, "-a", "sm3"}},
		{0, "hash", []string{a, "-a", "all"}},
		{2, "cmp", []string{a, b}},     // cmp 已删除
		{2, "check", []string{a, md5}}, // check 已并入 verify
		{2, "nosuch", nil},
	}
	for _, k := range checks {
		if got := code(t, k.cmd, k.args...); got != k.want {
			t.Errorf("%s %v = %d want %d", k.cmd, k.args, got, k.want)
		}
	}

	sums := w("SUMS.txt", md5+"  a.txt\n"+sha+" *b.txt\n")
	if got := code(t, "verify", sums); got != 0 {
		t.Errorf("verify=%d", got)
	}
	sums = w("SUMS.txt", md5+"  c.txt\n")
	if got := code(t, "verify", sums); got != 1 {
		t.Errorf("verify bad=%d", got)
	}
	sums = w("SUMS.txt", md5+"  a.txt\n"+sha+"  b.txt\n")
	if got := code(t, "verify", sums, "-a", "sha256"); got != 2 { // 清单含 MD5 行,与 -a 不符
		t.Errorf("verify -a sha256 with md5 line=%d", got)
	}
	sums = w("SUMS.txt", "SM3 (a.txt) = "+sm3+"\n") // 清单中的 SM3 标签不再支持
	if got := code(t, "verify", sums); got != 2 {
		t.Errorf("verify sm3 tag=%d", got)
	}

	// gen → verify 闭环:清单写在被扫描目录内,自身不应出现在条目里
	g := filepath.Join(p, "g")
	os.MkdirAll(filepath.Join(g, "sub"), 0o755)
	os.WriteFile(filepath.Join(g, "app.jar"), []byte("abc"), 0o644)
	os.WriteFile(filepath.Join(g, "sub", "b.sql"), []byte("abd"), 0o644)
	gs := filepath.Join(g, "SHA256SUMS.txt")
	for i := 0; i < 2; i++ { // 第二次清单已存在,仍应排除自身
		if got := code(t, "hash", g, "-r", "-o", gs); got != 0 {
			t.Errorf("gen -r=%d", got)
		}
	}
	if data, _ := os.ReadFile(gs); strings.Count(string(data), "\n") != 2 || !strings.Contains(string(data), "  sub/b.sql\n") {
		t.Errorf("清单内容不符:\n%s", data)
	}
	if got := code(t, "verify", gs); got != 0 {
		t.Errorf("verify gen=%d", got)
	}
	if got := code(t, "hash", g, "-o", gs); got != 0 { // 默认不递归
		t.Errorf("gen=%d", got)
	}
	if data, _ := os.ReadFile(gs); strings.Count(string(data), "\n") != 1 {
		t.Errorf("非递归应只有 1 项:\n%s", data)
	}
	code(t, "hash", g, "-r", "-o", gs)
	os.WriteFile(filepath.Join(g, "app.jar"), []byte("tampered"), 0o644)
	if got := code(t, "verify", gs); got != 1 {
		t.Errorf("verify tampered=%d", got)
	}
	if got := code(t, "hash", g, "-a", "all"); got != 0 {
		t.Errorf("hash -a all=%d", got)
	}
	// SM3 输出带算法标签的行,verify 不支持 SM3 标签
	sm3sums := filepath.Join(p, "sm3sums.txt")
	if got := code(t, "hash", g, "-a", "sm3", "-o", sm3sums); got != 0 {
		t.Errorf("hash -a sm3 -o=%d", got)
	}
	if data, _ := os.ReadFile(sm3sums); !strings.Contains(string(data), "SM3 (app.jar) = ") {
		t.Errorf("SM3 输出格式不符:\n%s", data)
	}
	if got := code(t, "verify", sm3sums); got != 2 {
		t.Errorf("verify sm3 清单=%d", got)
	}
	if got := code(t, "gen", g); got != 2 { // gen 已并入 hash
		t.Errorf("gen=%d", got)
	}
	if got := code(t, "hash", filepath.Join(p, "nosuch")); got != 2 {
		t.Errorf("gen nosuch=%d", got)
	}
	if got := code(t, "hash"); got != 2 {
		t.Errorf("gen 无参数=%d", got)
	}

	l, r := filepath.Join(p, "l"), filepath.Join(p, "r")
	os.MkdirAll(l, 0o755)
	os.MkdirAll(r, 0o755)
	os.WriteFile(filepath.Join(l, "x"), []byte("1"), 0o644)
	os.WriteFile(filepath.Join(r, "x"), []byte("1"), 0o644)
	if got := code(t, "dir", l, r); got != 0 {
		t.Errorf("dir=%d", got)
	}
	os.WriteFile(filepath.Join(l, "y"), []byte("2"), 0o644)
	if got := code(t, "dir", l, r, "-a", "all"); got != 1 {
		t.Errorf("dir diff=%d", got)
	}
	if got := code(t, "dir", l, r, "-a", "sm3"); got != 2 {
		t.Errorf("dir -a sm3=%d", got)
	}
	// 默认只比较第一层;子目录里的差异需 -r 才会发现
	os.Remove(filepath.Join(l, "y"))
	os.MkdirAll(filepath.Join(l, "sub"), 0o755)
	os.WriteFile(filepath.Join(l, "sub", "z"), []byte("3"), 0o644)
	if got := code(t, "dir", l, r); got != 0 {
		t.Errorf("dir 非递归=%d", got)
	}
	if got := code(t, "dir", l, r, "-r"); got != 1 {
		t.Errorf("dir -r=%d", got)
	}
}
