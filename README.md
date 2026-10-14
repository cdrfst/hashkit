# hashkit(Go 版)

用 Go 编写的文件哈希计算与校验小工具,支持 **MD5** 和 **SHA-256**;`hash` 命令另支持 **SM3(国密)** 计算。

用于核对文件在传输、交付、发布过程中是否被改动,例如投产前校验各开发组提交的文件、核对待发布文件与生产环境文件的差异。各命令的参数与示例见下文。

## 构建与测试

```bash
go build -o bin/hashkit .          # Windows: go build -o bin/hashkit.exe .
go test ./...
# 交叉编译 Windows 版
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o dist/hashkit.exe .
```

## 目标服务器(麒麟 V10 x86_64 / glibc 2.28 / 内核 4.19)

在任意机器上交叉编译为**纯静态**程序(不依赖 glibc,服务器无需安装 Go):

```bash
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o dist/hashkit-linux-amd64 .
```

上传后 `chmod +x hashkit-linux-amd64` 即可运行。如需 ARM 版(飞腾/鲲鹏),把 `GOARCH` 改为 `arm64`。

需要 Go 1.26+(`hash` 命令的 SM3 依赖 `github.com/emmansun/gmsm`;较新的 Go 会自动下载所需工具链)。

## 命令一览

只有三个命令,按"算 → 验 → 比"的顺序对应三类需求:

| 命令 | 解决的问题 | 一句话说明 |
|------|-----------|-----------|
| `hash` | 这些文件的哈希是多少?给我一份清单 | 计算文件或目录的哈希并输出清单 |
| `verify` | 这些文件和给定的哈希(或清单)一致吗? | 校验单个文件或按清单批量校验 |
| `dir` | 这两个目录里的文件一致吗? | 对比两个目录,报告相同、不同、仅一侧存在的文件 |

典型流程:发送方用 `hash` 生成清单,接收方用 `verify` 校验;需要与生产环境核对文件名和内容时,用 `dir`。

## 通用约定

### 通用选项

| 选项 | 适用命令 | 含义 | 默认值 |
|------|---------|------|--------|
| `-a 算法` | hash、verify、dir | 指定哈希算法,取值见下表 | `hash`、`dir` 为 `sha256`;`verify` 为 `all`(自动识别) |
| `-r` | hash、dir | 递归处理子目录 | 不递归,只处理目录第一层的文件 |

`-a` 的取值:

| 取值 | hash | verify | dir | 说明 |
|------|:---:|:---:|:---:|------|
| `md5` | ✔ | ✔ | ✔ | MD5 |
| `sha256`(或 `sha-256`) | ✔ | ✔ | ✔ | SHA-256 |
| `sm3` | ✔ | ✘ | ✘ | 国密 SM3,仅 `hash` 支持 |
| `all` | ✔(MD5、SM3、SHA-256) | ✔(不限定,自动识别) | ✔(MD5、SHA-256) | 全部可用算法 |

选项可以写在位置参数之前或之后,`hashkit hash -a md5 a.jar` 与 `hashkit hash a.jar -a md5` 等价。

### 退出码

| 退出码 | 含义 |
|--------|------|
| 0 | 全部一致 / 计算成功 |
| 1 | 存在不一致(`verify` 中文件读不到也算) |
| 2 | 运行出错(参数错误、文件不存在、清单无法解析等) |

可直接用于脚本判断,例如 `hashkit verify SHA256SUMS.txt && echo 通过 || echo 失败`。

### 算法识别规则

`verify` 不需要指定算法,按以下规则识别:

- 哈希值 32 位十六进制 → MD5。
- 哈希值 64 位十六进制 → SHA-256。
- 清单行带 `MD5` 或 `SHA256` 标签 → 按标签精确匹配。

### 清单文件格式

`hash` 输出和 `verify` 读取的清单,支持两种行格式,可在同一文件中混用。空行和以 `#` 开头的行被忽略,UTF-8 带 BOM 的文件可正常读取。

```text
# md5sum 风格:哈希  路径(两个空格;路径前的 * 会被忽略)
0227ddecdc5b1db84d9e877b3c4bae2f  app.jar
60adeb44bbc9eb4fac944bfe0c87d6938c75757264c69ae748765ed3ba257b2a  conf/a.properties

# 带算法标签的风格:算法 (路径) = 哈希
MD5 (lib.jar) = e8acc63b1e238f3255c900eed37254b8
SHA256 (lib.jar) = 76b5a357391276b282a516f54f48ef3c207f46d8192dc58c208d5183d38415f8
```

路径一律使用 `/` 分隔;清单中的 `SM3` 标签行 `verify` 不支持,会报"无法解析"。

## 命令详解

### hash:计算哈希并输出清单

#### 语法

```
hashkit hash <文件或目录>... [-a md5|sm3|sha256|all] [-o 输出文件] [-r]
```

#### 参数说明

| 参数 | 必填 | 说明 |
|------|:---:|------|
| `<文件或目录>...` | 是 | 一个或多个文件或目录 |
| `-a` | 否 | 算法,默认 `sha256`。`md5`、`sha256` 输出 md5sum 风格;`sm3`、`all` 输出带算法标签的风格 |
| `-o 输出文件` | 否 | 把结果写入文件;不写则输出到屏幕。写入成功后在屏幕打印"已写入 N 项 -> 文件" |
| `-r` | 否 | 递归子目录。不加时,目录只取第一层文件,并在屏幕提示"已跳过 N 个子目录" |

#### 路径规则

- **目录参数**:清单中的路径为相对该目录的路径(用 `/` 分隔),按路径排序,每次输出顺序固定。
- **文件参数**:清单中的路径为文件名,不含所在目录。
- 目录中只处理普通文件,符号链接等会被跳过;直接作为参数传入的符号链接会跟随到目标文件计算。
- 多个参数产生相同路径(例如两个目录里都有 `app.jar`)时报错,不会静默覆盖。
- `-o` 指定的文件位于被扫描目录内时,该文件自身会被自动排除,重复生成不会把旧清单算进去。

#### 示例

**1. 计算单个文件(默认 SHA-256)**

```bash
$ hashkit hash app.jar
60adeb44bbc9eb4fac944bfe0c87d6938c75757264c69ae748765ed3ba257b2a  app.jar
```

**2. 指定算法为 MD5**

```bash
$ hashkit hash app.jar -a md5
0227ddecdc5b1db84d9e877b3c4bae2f  app.jar
```

**3. 计算多个文件**

```bash
$ hashkit hash app.jar lib.jar
60adeb44bbc9eb4fac944bfe0c87d6938c75757264c69ae748765ed3ba257b2a  app.jar
76b5a357391276b282a516f54f48ef3c207f46d8192dc58c208d5183d38415f8  lib.jar
```

**4. 对整个发布目录递归生成清单,并保存到目录内**

```bash
$ hashkit hash release/ -r -o release/SHA256SUMS.txt
已写入 3 项 -> release/SHA256SUMS.txt

$ cat release/SHA256SUMS.txt
60adeb44bbc9eb4fac944bfe0c87d6938c75757264c69ae748765ed3ba257b2a  app.jar
9246d2c0e0f213ae2b86ac78a432a55edfd31d07a072331d58763c08d5292212  conf/a.properties
76b5a357391276b282a516f54f48ef3c207f46d8192dc58c208d5183d38415f8  lib.jar
```

**5. 不加 `-r` 时只处理第一层**

```bash
$ hashkit hash release/
提示: 已跳过 1 个子目录,如需包含请加 -r
60adeb44bbc9eb4fac944bfe0c87d6938c75757264c69ae748765ed3ba257b2a  app.jar
76b5a357391276b282a516f54f48ef3c207f46d8192dc58c208d5183d38415f8  lib.jar
```

提示信息输出到标准错误,不会混入重定向到文件的清单内容。

**6. 计算国密 SM3,或同时输出全部算法**

```bash
$ hashkit hash lib.jar -a sm3
SM3 (lib.jar) = 89417eae7f1b98e26889f3b58ed44d4093819c68632e07d34dcf3c2b612bdca7

$ hashkit hash lib.jar -a all
MD5 (lib.jar) = e8acc63b1e238f3255c900eed37254b8
SM3 (lib.jar) = 89417eae7f1b98e26889f3b58ed44d4093819c68632e07d34dcf3c2b612bdca7
SHA256 (lib.jar) = 76b5a357391276b282a516f54f48ef3c207f46d8192dc58c208d5183d38415f8
```

SM3 行只用于查看和人工核对,`verify` 不校验 SM3。

**7. 比较两个文件是否一致**

分别计算,对比输出的哈希值即可:

```bash
hashkit hash a.jar
hashkit hash b.jar
```

### verify:校验文件

`verify` 有两种用法,按位置参数的个数区分:**1 个参数是清单,2 个参数是文件加哈希值**。

#### 语法

```
hashkit verify <校验文件>      [-C 目录] [-a md5|sha256|all]     # 批量:按清单校验
hashkit verify <文件> <哈希值>           [-a md5|sha256|all]     # 单个:与给定哈希值比对
```

#### 参数说明

| 参数 | 必填 | 适用模式 | 说明 |
|------|:---:|:---:|------|
| `<校验文件>` | 清单模式必填 | 批量 | 清单文件,格式见“清单文件格式” |
| `<文件>` `<哈希值>` | 单个模式必填 | 单个 | 待校验文件和期望哈希值,哈希值不区分大小写 |
| `-C 目录` | 否 | 仅批量 | 被校验文件所在目录。不写时取清单文件所在目录 |
| `-a` | 否 | 两种 | 约束允许的算法,默认 `all`(不限定,自动识别)。显式指定时,清单中或给定的哈希必须是该算法,否则报错退出(退出码 2),用于防止拿错算法的哈希值 |

#### 输出说明

每个文件一行,最后一行为合计:

| 输出 | 含义 |
|------|------|
| `文件: 通过 ✔ [算法]` | 哈希一致 |
| `文件: 不一致 ✘` + 期望/实际 | 哈希不一致 |
| `文件: 无法读取 (原因)` | 文件不存在或无权限,计入失败 |

#### 示例

**1. 按清单校验(清单与文件在同一目录)**

```bash
$ hashkit verify release/SHA256SUMS.txt
app.jar: 通过 ✔ [SHA256]
conf/a.properties: 通过 ✔ [SHA256]
lib.jar: 通过 ✔ [SHA256]

合计 3 项:通过 3,不一致 0,无法读取 0
```

**2. 清单与文件不在同一目录,用 `-C` 指定文件所在目录**

```bash
hashkit verify SHA256SUMS.txt -C /data/downloads/release
```

**3. 文件被改动时**

```bash
$ hashkit verify release/SHA256SUMS.txt
app.jar: 通过 ✔ [SHA256]
conf/a.properties: 通过 ✔ [SHA256]
lib.jar: 不一致 ✘
  期望: 76b5a357391276b282a516f54f48ef3c207f46d8192dc58c208d5183d38415f8
  实际 [SHA256]: 7e0a9086ff409c991d219dae7b27873ad220a70e7283349fe0ba7fd58deb6cfc

合计 3 项:通过 2,不一致 1,无法读取 0
$ echo $?
1
```

**4. 校验单个文件(开发人员直接发来一个哈希值)**

```bash
$ hashkit verify app.jar 60adeb44bbc9eb4fac944bfe0c87d6938c75757264c69ae748765ed3ba257b2a
app.jar: 通过 ✔ [SHA256]

合计 1 项:通过 1,不一致 0,无法读取 0
```

32 位哈希按 MD5 校验:

```bash
hashkit verify app.jar 0227ddecdc5b1db84d9e877b3c4bae2f
```

**5. 用 `-a` 防止算法弄错**

要求对方必须提供 SHA-256,收到的却是 MD5 值时:

```bash
$ hashkit verify app.jar 0227ddecdc5b1db84d9e877b3c4bae2f -a sha256
错误: app.jar: 哈希对应 MD5,与 -a 指定的算法不符
$ echo $?
2
```

**6. 在脚本中作为门禁**

```bash
if hashkit verify release/SHA256SUMS.txt > verify.log; then
  echo "校验通过,允许投产"
else
  echo "校验未通过,详见 verify.log"; exit 1
fi
```

#### 注意

- 清单里的文件名与实际文件名不一致(包括大小写)时,该文件显示"无法读取",并使退出码为 1。
- `-C` 只用于清单模式;单个模式下使用会报错。
- `verify` 只校验清单列出的文件,不会发现目录里多出来、清单没写的文件。需要发现多余文件时,可结合 `dir` 使用。

### dir:对比两个目录

#### 语法

```
hashkit dir <目录A> <目录B> [-a md5|sha256|all] [-r] [-v]
```

#### 参数说明

| 参数 | 必填 | 说明 |
|------|:---:|------|
| `<目录A>` `<目录B>` | 是 | 两个待对比目录,A 称为"左侧",B 称为"右侧" |
| `-a` | 否 | 算法,默认 `sha256`;`all` 表示 MD5 和 SHA-256 各比一次 |
| `-r` | 否 | 递归子目录。不加时只比较第一层文件,并提示跳过的子目录数(左右两侧合计) |
| `-v` | 否 | 同时列出内容一致的文件;不加时只列出有差异的文件 |

文件按相对路径配对,文件名(包括版本号)不同的两个文件不会被当作同一个文件。

#### 输出说明

首行为统计:`一致 | 不同 | 仅左侧 | 仅右侧 | 出错`,之后逐条列出:

| 标记 | 含义 |
|------|------|
| `=` | 两侧都有,内容一致(仅 `-v` 时显示) |
| `≠` | 两侧都有同名文件,内容不同 |
| `<` | 只在左侧(目录 A)存在 |
| `>` | 只在右侧(目录 B)存在 |
| `!` | 读取出错,后跟原因 |

只要存在 `≠`、`<`、`>`、`!` 任意一种,退出码为 1。

#### 示例

**1. 对比待发布目录与生产目录(只比第一层)**

```bash
$ hashkit dir release/ /mnt/prod/app/
[SHA256] 一致 1 | 不同 1 | 仅左侧 1 | 仅右侧 1 | 出错 0
  ≠  app.jar
  <  order-1.2.1.jar  (仅 release/)
  >  order-1.2.0.jar  (仅 /mnt/prod/app/)
提示: 已跳过 2 个子目录,如需包含请加 -r
```

读法:`app.jar` 同名但内容不同,是正常的版本更新;`order-1.2.1.jar` 与 `order-1.2.0.jar` 只差版本号,说明开发人员改了文件名,需要退回让其改成与生产一致。

**2. 递归对比并显示一致的文件**

```bash
$ hashkit dir release/ /mnt/prod/app/ -r -v
[SHA256] 一致 1 | 不同 2 | 仅左侧 1 | 仅右侧 1 | 出错 0
  =  lib.jar
  ≠  app.jar
  ≠  conf/a.properties
  <  order-1.2.1.jar  (仅 release/)
  >  order-1.2.0.jar  (仅 /mnt/prod/app/)
```

**3. 只关心文件名是否一致(检查 `<` 与 `>`)**

发新版本时 `≠` 必然出现,`dir` 会返回 1,所以判断文件名一致时,看 `<`、`>` 是否为空:

```bash
if hashkit dir release/ /mnt/prod/app/ 2>/dev/null | grep -qE '^  [<>]  '; then
  echo "文件名与生产环境不一致"
else
  echo "文件名一致"
fi
```

**4. 用 MD5 与 SHA-256 各比一次**

```bash
hashkit dir release/ /mnt/prod/app/ -a all
```

#### 注意

- 目录里如果放着清单文件(如 `SHA256SUMS.txt`),它也会作为一个文件参与对比,在统计中显示为 `<` 或 `>`,判断时可忽略,或先把清单移出目录。
- 文件名区分大小写,`App.jar` 与 `app.jar` 会被判为两个文件。
- 两个目录需要在同一台机器上可访问(本地、挂载或拷贝过来)。无法直接访问对方目录时,改用"一侧 `hash` 生成清单,另一侧 `verify`"的方式。

## 典型场景

### 场景一:校验开发人员交付的文件

1. 开发人员在交付目录生成清单并一并发送:

   ```bash
   hashkit hash delivery/ -r -o delivery/SHA256SUMS.txt
   ```

   没有本工具时,Linux 下 `sha256sum 文件... > SHA256SUMS.txt` 生成的清单同样可用。

2. 接收方校验:

   ```bash
   hashkit verify delivery/SHA256SUMS.txt
   ```

3. 退出码为 0 方可进入下一步。

### 场景二:核对待发布文件与生产环境的差异

```bash
hashkit verify delivery/SHA256SUMS.txt                     # 1. 文件完整性
hashkit dir delivery/ /mnt/prod/app/lib/ -r                # 2. 与生产环境对比,关注 < 与 >
```

### 场景三:对方只给了一个哈希值

```bash
hashkit verify app.jar <对方提供的哈希值>
```

### 场景四:生成并保留校验记录

```bash
hashkit verify delivery/SHA256SUMS.txt | tee verify-$(date +%F).log
```

## 注意事项

1. **清单与文件不要走同一个渠道**:清单和文件一起被替换时,校验仍然会通过。涉及生产的文件,建议通过另一个渠道(如工单系统或企业即时消息)再核对一次哈希值。校验能证明文件没有损坏或被改动,不能证明文件来源可信。
2. **换行符会改变哈希值**:文本类文件(`.sql`、`.sh`、`.properties`)经 Git 或 Windows 转换换行符后,哈希值会变化。校验失败时先排查这一点。
3. **SM3 只能计算,不能校验**:SM3 值需要人工核对,清单中带 `SM3` 标签的行 `verify` 会报"无法解析"。
4. **文件名限制**:含换行符的文件名无法写入清单,`hash` 会报错。
5. **不支持的旧命令**:早期版本中的 `cmp`、`check`、`gen` 已移除。对应关系:`check <文件> <哈希值>` → `verify <文件> <哈希值>`;`gen <目录>` → `hash <目录>`;`cmp A B` → 分别用 `hash` 计算后对比。

## 目录结构

```
main.go                  命令行入口
hashkit/hashkit.go       核心库:哈希、校验文件解析、目录对比
hashkit/hashkit_test.go  标准测试向量等单元测试
main_test.go             命令行行为测试
```

## 在 VS Code 中调试

1. 安装 VS Code 扩展 **Go**(golang.go);首次打开 `.go` 文件时按提示安装 `dlv`(Delve 调试器),或执行 `go install github.com/go-delve/delve/cmd/dlv@latest`。
2. 打开项目根目录(含 `go.mod`),新建 `.vscode/launch.json`:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "name": "调试: hash",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}",
      "args": ["hash", "${workspaceFolder}/go.mod", "-a", "all"]
    },
    {
      "name": "调试: verify 单个文件",
      "type": "go",
      "request": "launch",
      "mode": "debug",
      "program": "${workspaceFolder}",
      "args": ["verify", "${workspaceFolder}/go.mod", "d41d8cd98f00b204e9800998ecf8427e"]
    },
    {
      "name": "调试: 当前测试文件",
      "type": "go",
      "request": "launch",
      "mode": "test",
      "program": "${fileDirname}"
    }
  ]
}
```

3. 在 `main.go` / `hashkit/hashkit.go` 行号左侧点击设置断点(如 `doVerify`、`HashReader`)。
4. 按 `F5` 选择配置启动;改 `args` 即可换命令与参数。
5. 单步:`F10` 跳过、`F11` 进入、`Shift+F11` 跳出、`F5` 继续。
6. 调试单个测试:测试函数上方的 **debug test** 链接。
7. 若断点不命中,可在配置里加 `"buildFlags": "-gcflags=all=-N -l"` 关闭优化;不要用 `-ldflags="-s -w"` 构建的程序调试。
