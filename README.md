# 证据审计存储系统（Go，第一版）

只记录**项目自己产生的应用事件**（构建、发布、审批等），不采集用户电脑活动。
第一版提供审计底座的三个核心能力：

- 追加记录（append-only，写入后 fsync）
- 批次封存（生成需要**外部保存**的封存摘要）
- 篡改检查（改写 / 插入 / 中间删除，以及凭外部摘要识别尾部截断）

## 存储格式

日志由若干定长头 + 变长体的帧顺序拼接：

    magic(2) | payloadLen(4, LE) | payload | sha256(32)

- 帧校验和覆盖 magic + len + payload，能发现任何字节改写。
- payload 末尾带 prevHash：上一条记录的帧哈希（首条为全零）。
  因此中间插入或删除一条，其后第一条的 prevHash 立即对不上。
- payload 含纳秒时间戳、事件类型、来源、事件 ID、不透明二进制数据。
- 查询（Scan）严格按文件顺序（即来源追加顺序）返回。

## 篡改模型（重要边界）

| 攻击 | 文件自身能否发现 | 方式 |
|---|---|---|
| 改写某条记录 | 能 | 帧 SHA-256 不匹配 |
| 中间插入记录 | 能 | 后继记录 prevHash 断裂 |
| 中间删除记录 | 能 | 后继记录 prevHash 断裂 |
| **尾部整条截断** | **不能（设计如此）** | 截断后剩余前缀仍是自洽链 |

尾部截断**不靠文件自身假装识别**。封存时生成 SealSummary（记录数、字节长度、
末条哈希、整文件 SHA-256），必须保存到日志之外（另一块盘 / 对象存储 / 签名回执）。
校验时用 VerifyAgainstSummary 比对该摘要才能发现删尾。

## 写入中断恢复

Open 重放整个文件：

- 末尾物理上没写完的帧（短帧）视为崩溃造成的 torn write，截断到最后一条完整记录；
- 但**帧中间**损坏（长度完整、校验和错）一律报 TamperError，不会被当成
  写入失败静默吞掉，避免把真实中间篡改伪装成崩溃。

## Go API

    l, _ := auditlog.Create("audit.log")
    l.Append(auditlog.Event{Time: time.Now().UTC(), EventType: "build.passed", Source: "ci", Data: payload})

    sum, _ := l.Seal("batch-2026-09-29")
    auditlog.WriteSummary("/external-store/batch-2026-09-29.json", sum) // 存到日志之外

    auditlog.VerifyChain("audit.log")                  // 只查链：改写/插入/中间删除；不能发现删尾
    s, _ := auditlog.ReadSummary("/external-store/batch-2026-09-29.json")
    auditlog.VerifyAgainstSummary("audit.log", s)      // 凭外部摘要：连删尾一起发现

    l.Scan(func(r auditlog.Record) error { ... })      // 按来源顺序遍历

## CLI

    go build -o evaudit ./cmd/evaudit
    evaudit init   audit.log
    evaudit append audit.log build.failed ci run-1 aGVsbG8=   # data 为 base64，可空
    evaudit list   audit.log                                  # 每行一条 JSON，保持来源顺序
    evaudit seal   audit.log batch-1 /secure/offhost-batch-1.json
    evaudit verify audit.log                                  # 只校验链
    evaudit verify audit.log /secure/offhost-batch-1.json     # 凭外部摘要校验（可发现删尾）

## 测试

auditlog/auditlog_test.go 在**真实改动后的副本**上验证，而不是只比较条数：

- 翻转副本中第三条 payload 的字节 → 检出改写
- 从副本中间物理删掉第二条帧 → 检出中间删除
- 把首条帧复制插入中间 → 检出插入
- 在帧边界删掉最后两条：VerifyChain 通过（自洽前缀），VerifyAgainstSummary
  报 TailTruncated → 证明删尾必须靠外部摘要
- 制造 torn append → Open 恢复到最后完整记录且之后可正常续写
- 中间帧损坏但长度完整 → Open 拒绝静默恢复

    go test ./...
