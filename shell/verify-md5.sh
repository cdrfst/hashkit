#!/bin/sh
# 按脚本所在目录下的 MD5.txt 校验该目录(含子目录)中的文件。
# 依赖:同目录下的 hashkit-linux-amd64(或 hashkit)和 MD5.txt。
# 退出码:0 全部一致 | 1 存在不一致或无法读取 | 2 出错

cd "$(dirname "$0")" || exit 2

if [ -x ./hashkit-linux-amd64 ]; then
    BIN=./hashkit-linux-amd64
elif [ -x ./hashkit ]; then
    BIN=./hashkit
else
    echo "错误: 当前目录未找到可执行的 hashkit-linux-amd64 (或 hashkit),请确认文件存在且已执行 chmod +x" >&2
    exit 2
fi

if [ ! -f ./MD5.txt ]; then
    echo "错误: 当前目录未找到清单文件 MD5.txt,请先运行 gen-md5.sh" >&2
    exit 2
fi

exec "$BIN" verify ./MD5.txt -C . -a md5
