package hashkit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func h(t *testing.T, s string, a Algo) string {
	t.Helper()
	r, err := HashReader(strings.NewReader(s), a)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestKnownVectors(t *testing.T) {
	cases := []struct {
		in   string
		a    Algo
		want string
	}{
		{"", MD5, "d41d8cd98f00b204e9800998ecf8427e"},
		{"abc", MD5, "900150983cd24fb0d6963f7d28e17f72"},
		{"abc", SM3, "66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0"},
		{strings.Repeat("abcd", 16), SM3, "debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732"},
		{"abc", SHA256, "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"},
	}
	for _, c := range cases {
		if got := h(t, c.in, c.a); got != c.want {
			t.Errorf("%s(%q)=%s want %s", c.a, c.in, got, c.want)
		}
	}
}

func TestDetectAndParse(t *testing.T) {
	if got, ok := Detect(strings.Repeat("a", 32)); !ok || got != MD5 {
		t.Error(got, ok)
	}
	if got, ok := Detect(strings.Repeat("A", 64)); !ok || got != SHA256 {
		t.Error(got, ok)
	}
	if _, ok := Detect("xyz"); ok {
		t.Error("xyz")
	}
	if _, ok := Detect(""); ok {
		t.Error("空串")
	}
	e, err := ParseChecksumText("# c\n900150983cd24fb0d6963f7d28e17f72  a.txt\nMD5 (b.txt) = d41d8cd98f00b204e9800998ecf8427e\n")
	if err != nil || len(e) != 2 || e[1].File != "b.txt" {
		t.Fatal(e, err)
	}
	if _, err := ParseChecksumText("garbage line"); err == nil {
		t.Error("expected error")
	}
}

func TestGenerateChecksums(t *testing.T) {
	root := t.TempDir()
	os.MkdirAll(filepath.Join(root, "sub"), 0o755)
	os.WriteFile(filepath.Join(root, "b.txt"), []byte("abc"), 0o644)
	os.WriteFile(filepath.Join(root, "a.txt"), []byte(""), 0o644)
	os.WriteFile(filepath.Join(root, "sub", "c.txt"), []byte("abc"), 0o644)
	sums := filepath.Join(root, "SUMS.txt")
	os.WriteFile(sums, []byte("old"), 0o644)

	// 默认只取第一层,跳过 1 个子目录,并排除清单自身
	es, skipped, err := GenerateChecksums([]string{root}, MD5, false, sums)
	if err != nil || skipped != 1 || len(es) != 2 || es[0].File != "a.txt" || es[1].File != "b.txt" {
		t.Fatal(es, skipped, err)
	}
	if es[0].Hash != "d41d8cd98f00b204e9800998ecf8427e" || es[1].Hash != "900150983cd24fb0d6963f7d28e17f72" {
		t.Error(es)
	}

	// 递归:包含子目录文件,路径使用 "/"
	es, skipped, err = GenerateChecksums([]string{root}, SHA256, true, sums)
	if err != nil || skipped != 0 || len(es) != 3 || es[2].File != "sub/c.txt" {
		t.Fatal(es, skipped, err)
	}

	// 输出可被解析且条目一致
	back, err := ParseChecksumText(FormatGNU(es))
	if err != nil || len(back) != len(es) {
		t.Fatal(back, err)
	}
	for i := range es {
		if back[i].File != es[i].File || back[i].Hash != es[i].Hash {
			t.Errorf("%v != %v", back[i], es[i])
		}
	}

	// 文件参数取文件名;不同目录同名文件报错
	es, _, err = GenerateChecksums([]string{filepath.Join(root, "sub", "c.txt")}, MD5, false, "")
	if err != nil || len(es) != 1 || es[0].File != "c.txt" {
		t.Fatal(es, err)
	}
	if _, _, err = GenerateChecksums([]string{filepath.Join(root, "sub", "c.txt"), filepath.Join(root, "sub", "c.txt")}, MD5, false, ""); err == nil {
		t.Error("expected duplicate error")
	}
	if _, _, err = GenerateChecksums([]string{filepath.Join(root, "nosuch")}, MD5, false, ""); err == nil {
		t.Error("expected not-exist error")
	}
}

func TestParseCommonAlgo(t *testing.T) {
	if _, err := ParseCommonAlgo("sm3"); err == nil {
		t.Error("sm3 应被拒绝")
	}
	if got, err := ParseCommonAlgo("all"); err != nil || len(got) != 2 || Contains(got, SM3) {
		t.Error(got, err)
	}
	if got, err := ParseCommonAlgo("SHA-256"); err != nil || len(got) != 1 || got[0] != SHA256 {
		t.Error(got, err)
	}
	if _, err := ParseCommonAlgo("zz"); err == nil {
		t.Error("未知算法应报错")
	}
	if got, err := ParseAlgo("all"); err != nil || len(got) != 3 {
		t.Error("hash 仍应支持三种算法", got, err)
	}
	if _, err := ParseChecksumText("SM3 (a) = " + strings.Repeat("a", 64)); err == nil {
		t.Error("清单中的 SM3 标签应无法解析")
	}
}

func TestCompareDirs(t *testing.T) {
	root := t.TempDir()
	l, r := filepath.Join(root, "l"), filepath.Join(root, "r")
	os.MkdirAll(filepath.Join(l, "sub"), 0o755)
	os.MkdirAll(r, 0o755)
	os.WriteFile(filepath.Join(l, "x"), []byte("1"), 0o644)
	os.WriteFile(filepath.Join(r, "x"), []byte("1"), 0o644)
	d, err := CompareDirs(l, r, SHA256, true)
	if err != nil || !d.Identical() {
		t.Fatal(d, err)
	}
	os.WriteFile(filepath.Join(l, "sub", "y"), []byte("2"), 0o644)
	os.WriteFile(filepath.Join(r, "x"), []byte("9"), 0o644)
	d, _ = CompareDirs(l, r, SHA256, true)
	if d.Identical() || len(d.OnlyLeft) != 1 || d.OnlyLeft[0] != "sub/y" || len(d.Different) != 1 {
		t.Fatal(d)
	}
	// 非递归:不看子目录,只比较第一层,并记录跳过的子目录数
	d, _ = CompareDirs(l, r, SHA256, false)
	if len(d.OnlyLeft) != 0 || len(d.Different) != 1 || d.Skipped != 1 {
		t.Fatal(d)
	}
}
