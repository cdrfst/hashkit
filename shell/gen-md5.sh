#!/bin/sh
# 生成脚本所在目录(含子目录)全部文件的 MD5 清单,写入同目录 MD5.txt。
# 清单不包含:hashkit 可执行文件、gen-md5 / verify-md5 脚本(.sh 与 .bat)、MD5.txt 自身
# (仅排除目录第一层的同名文件,子目录中的同名文件仍会计入)。
# 依赖:同目录下的 hashkit-linux-amd64(或 hashkit)。
# 退出码:0 成功 | 2 出错

cd "$(dirname "$0")" || exit 2

if [ -x ./hashkit-linux-amd64 ]; then
    BIN=./hashkit-linux-amd64
elif [ -x ./hashkit ]; then
    BIN=./hashkit
else
    echo "错误: 当前目录未找到可执行的 hashkit-linux-amd64 (或 hashkit),请确认文件存在且已执行 chmod +x" >&2
    exit 2
fi

# 先写入系统临时目录,避免临时文件被计入清单
TMP=$(mktemp) || exit 2
trap 'rm -f "$TMP"' EXIT

"$BIN" hash . -r -a md5 > "$TMP" || exit 2

# 清单行格式为"32 位 MD5 + 两个空格 + 相对路径",路径从第 35 个字符开始
awk '
BEGIN {
    n = split("hashkit-linux-amd64 hashkit hashkit.exe gen-md5.sh gen-md5.bat verify-md5.sh verify-md5.bat MD5.txt", a, " ")
    for (i = 1; i <= n; i++) skip[a[i]] = 1
}
!(substr($0, 35) in skip)
' "$TMP" > ./MD5.txt

COUNT=$(wc -l < ./MD5.txt | tr -d ' ')
if [ "$COUNT" -eq 0 ]; then
    rm -f ./MD5.txt
    echo "错误: 排除工具文件后没有可计算哈希的文件" >&2
    exit 2
fi
echo "已写入 $COUNT 项 -> ./MD5.txt"
