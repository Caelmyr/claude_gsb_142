# DFSVS — 分布式文件存储与版本控制系统

> **本副本为「缺陷注入与修复题」基准版本**：在完整可运行系统之上注入了
> 10 个跨层后端缺陷（5 地狱 + 5 困难），对应 `BUG_TASKS.md` 中的 10 道修复题；
> 地狱级缺陷的候选注入位置见 `CANDIDATE_SITES.md`。
> 注入均为「结果错误但流程正常」型：服务可正常启动、页面可正常渲染、
> 接口不返回 5xx、无崩溃/死锁/未捕获异常；前端代码未被修改，仅作观察窗口。
> 若要获取无缺陷的干净实现，请按 `BUG_TASKS.md` 完成修复或对照题目逐项还原。

纯 Python（标准库，零第三方依赖）+ 原生 HTML/CSS/JS 实现的**教学级分布式文件系统**：
模拟 HDFS 风格的 NameNode / DataNode 集群（节点间全 HTTP 通信），
在其上叠加 Git 风格的版本控制（提交 / 分支 / 三方合并 / 检出），
并提供 12 个页面的管理控制台（含**敏感目录落盘加密 + 密钥轮换**）。

代码规模：**约 13,000 行**（后端 ~9,300 行 Python，前端 ~4,700 行 HTML/CSS/JS）。

---

## 1. 快速开始

```bash
# 依赖：Python 3.10+（仅标准库）；无 pip 安装步骤
python3 run.py                  # 启动 NameNode(:8020) + 3 个 DataNode(:8021-8023)，首次自动注入演示数据
python3 run.py --datanodes 4    # 4 个 DataNode
python3 run.py --reset          # 清空 data/ 后重建（重新注入种子数据）
python3 run.py --no-seed        # 空集群启动
```

浏览器打开 <http://127.0.0.1:8020/>（控制台会自动以 `admin/admin123` 登录）。

| 账号 | 口令 | 角色 |
|---|---|---|
| admin | admin123 | 管理员（含故障演练 / 用户 / 权限管理） |
| alice | alice123 | 运维员 |
| bob | bob12345 | 只读用户 |
| carol | carol123 | 运维员（已停用，演示账号状态位） |

把 DataNode 作为独立进程扩容（HTTP 自动注册进集群）：

```bash
python3 -m backend.datanode --id dn5 --port 8025
```

---

## 2. 前端页面（12 个，要求 10 个 + 仪表盘）

| 页面 | 文件 | 内容 |
|---|---|---|
| 仪表盘 | `index.html` | KPI / 容量水位 / 最近提交 / 事件流 / 热点 TOP |
| 文件浏览 | `files.html` | 目录树（**加密目录 🔒 标记**）+ 缩略图网格 + 面包屑 + 块/副本详情抽屉（含密文块标记）+ 文本预览 |
| 上传下载 | `transfer.html` | 分块上传（分片可视化、暂停/续传/混沌模式；**分片暂存同样加密落盘**）、Range 分段下载（断点续传、sha256 校验、副本命中统计） |
| 版本历史 | `versions.html` | 提交时间线（泳道）、分支管理、提交/合并/检出、冲突展示、文件级历史与回滚 |
| 差异对比 | `diff.html` | 版本 diff + 文本 diff 双模式、Myers/Patience/difflib 选择、unified/双栏视图、行内字符级高亮、大文件性能试验台 |
| 节点状态 | `nodes.html` | 节点卡片（心跳/容量/IO/版本向量）、块×节点副本矩阵、恢复队列、杀死/复活/注入损坏演练、实时事件流 |
| 存储统计 | `stats.html` | 容量 donut、副本数分布、块大小直方图、24h 吞吐、容量趋势、类型分布、热度榜（sparkline）、元数据文档表 |
| 用户管理 | `users.html` | 用户 CRUD、角色能力矩阵、活动会话与吊销 |
| 权限设置 | `permissions.html` | 路径前缀 ACL 规则编辑器、默认策略、**判定轨迹测试器** |
| 加密安全 | `crypto.html` | **已加密目录、各密钥版本指纹/用量、密钥轮换入口、查看密钥（二次口令）、落盘明文验证** |
| 系统日志 | `logs.html` | 级别/来源/用户/关键字过滤、分页、展开详情、自动刷新、CSV 导出、清空 |
| 回收站 | `recycle.html` | 保留期倒计时、恢复 / 彻底删除 / 清空 |

共享样式 `frontend/css/app.css`（暗色设计系统），共享脚本 `frontend/js/app.js`
（令牌管理、API 封装、导航、吐司/弹窗、SVG 图表库）。

---

## 3. 架构

```
┌──────────────────────────── 浏览器（11 页面）────────────────────────────┐
│  fetch /api/*（JSON）· /api/download（Range）· /api/thumbnail           │
└───────────────────────────────────┬──────────────────────────────────────┘
                                    │ HTTP（Bearer 令牌 + 路径 ACL）
┌───────────────────────────────────▼──────────────────────────────────────┐
│  NameNode :8020 （backend/namenode.py + http_server.py）                  │
│   · 元数据 9 个 JSON 文档：fs/blocks/versions/users/perms/                │
│     logs/recycle/stats/cluster   —— 原子写 + 版本向量                     │
│   · 块表（genstamp/校验和/副本位置）、放置策略、恢复调度、GC                │
│   · 上传会话（断点续传暂存）、Range 读路径（副本轮询+故障转移）              │
│   · 版本树 VersionStore（提交/分支/merge/checkout）                        │
└──────┬───────────────────────────────────────────────────▲───────────────┘
       │ PUT /block（流水线复制 X-Forward-To）   心跳/块汇报/事件（JSON）
       │ GET /block（读、Range）                 恢复命令随心跳应答下发
       │                                         cluster 文档按版本向量拉取
┌──────▼───────────────────────────────────────────────────┴───────────────┐
│  DataNode :8021..:8024 （backend/datanode.py，可独立进程运行）              │
│   · blocks/<blk>.dat + node_state.json（原子写）                           │
│   · 心跳线程 / 全量块汇报线程 / 数据巡检(scrub)线程 / 持久化线程             │
│   · 流水线转发、拉取式再复制、静默损坏自发现                                 │
└───────────────────────────────────────────────────────────────────────────┘
```

元数据目录布局（`data/`，全部 JSON，崩溃安全）：

```
data/meta/{fs,blocks,versions,users,perms,logs,recycle,stats,cluster}.json
data/sessions/<upload_id>/piece_000000      # 上传分片暂存
data/datanodes/<node_id>/blocks/<blk>.dat   # 块本体
data/datanodes/<node_id>/node_state.json    # DN 索引（原子写）
data/datanodes/<node_id>/doc_cache/*.json   # DN 同步到的元数据文档
```

---

## 4. 五大难点的实现

### 4.1 分块策略与副本一致性
* **两种分块**（`chunking.py`）：固定 64KiB；CDC 内容定义分块
  （Buzhash 滚动哈希，O(1) 滑窗，min/avg/max 约束）。
  冒烟测试验证：头部插入 16B 后 CDC 11/12 块不变（去重友好），
  固定分块则几乎全部错位。
* **内容去重**：块表维护 `by_checksum` 索引，相同内容块直接复用。
* **流水线复制**：NN PUT → DN1 → DN2 → DN3（`X-Forward-To` 链式头），
  每一跳 sha256 校验；应答嵌套展平后登记副本（含每一跳的 ack）。
* **副本一致性**：每块 `genstamp` 单调递增；块汇报对账时
  未知块/旧 genstamp/校验和不符 → 下发删除命令；
  存活副本 < 期望 → 进入 under-replicated 队列。

### 4.2 节点故障检测与自动恢复
* 心跳 1.5s；>3.6s 标 SUSPECT，>6s 判 DEAD → 其上副本全部失效评估。
* 恢复调度线程每 2s：为缺副本块选「存活好副本(源) → 空闲节点(目标)」，
  命令随该节点下次心跳应答下发；目标 DN 用 HTTP 从源拉取块。
* **坏副本主动替换**：corrupt / stale 副本先下发删除并摘除记录，
  使该节点重新成为复制候选，保证队列可收敛（不会卡死）。
* 节点复活后强制全量块汇报对账；孤儿块（磁盘有、索引无）清理。
* **静默损坏**：DN scrub 线程抽样重算校验和；读路径 NN 侧二次校验 +
  副本故障转移；注入演练见 `POST /api/sim/corrupt`。

### 4.3 版本树冲突合并
* 提交 = 全量快照 + 块引用（块不可变 ⇒ 历史版本天然可读；
  GC 保护集 = 活动 inode ∪ 全部提交快照）。
* 合并：base = LCA；快照级三方状态机（单侧变更采纳 / 双侧同内容采纳 /
  增删冲突保留修改侧）；文本双侧异改 → 行级 diff3（见 4.4），
  冲突写 `<<<<<<< / ======= / >>>>>>>` 标记并提交为待解决状态；
  二进制冲突保留 ours 并记录。合并产生双亲 commit。
* 检出 = 快照物化回活动 inode 树；工作区脏时自动提交保护（不丢数据）；
  快进合并自动识别。

### 4.4 大文件差异对比性能（diff_engine.py）
* **Myers O(ND)**：贪心 + 轨迹回溯，带公共前缀/后缀裁剪；
  轨迹内存保护 D>900 自动降级。
* **Patience**：唯一行锚点 + LIS（O(n log n)）分治，
  锚点间小段回退 Myers / 大段 difflib。
* `auto`：小输入直接 Myers，大输入 Patience。
  实测 20k 行 / 5% 修改 ≈ 85ms（907 个差异段）。
* 三方合并 `merge3`：diff3 语义，闭区间重叠判定（含相邻零宽插入），
  重叠且不同 → 冲突块；相同 → 采纳其一。
* 渲染：unified / 双栏 / 行内字符级高亮；统计与计时返回前端展示。

### 4.5 JSON 元数据多节点同步：原子写 + 版本向量
* **原子写**（`util.atomic_write_*`）：同目录临时文件 → flush → fsync →
  `os.replace` → 目录 fsync；读者永远看到完整旧/新文件。
  块文件、分片暂存、DN 索引同样走原子写。
* **版本向量**：每个文档 `vv = {node_id: 逻辑时钟}`，本地 `touch()` 推进分量；
  DN 心跳携带 `doc_vv`，NN 比较后返回 `pull_docs`；
  DN 拉取信封按 `vv_compare` 判定：
  after→采纳 / before|equal→跳过 / **concurrent→冲突**（cluster 文档以 NN 为权威，
  合并 vv 并留 `doc_synced(conflict-nn-wins)` 审计事件）。
* **锁序纪律**：全局固定 meta → node → health → cmd，
  心跳注册/复活等路径在锁外执行副作用，避免 ABBA 死锁。

### 4.6 敏感文件落盘加密 + 密钥轮换（`crypto.py` / `keystore.py`）
* **加密边界在 NameNode**：写入时块在 NN 内存中封包后才经流水线复制到
  DataNode；DN 磁盘上的 `blocks/<blk>.dat` 是 `DFSENC1` 密文容器
  （JSON 头记录 kid/nonce/HMAC 标签 + 密文），**密钥绝不下发到 DN**。
  上传分片暂存目录 `data/sessions/` 同样用会话临时密钥（仅内存）封包。
* **算法（零依赖，标准库）**：HMAC-SHA256 为核心的 CTR 流密码，
  每块 16B 随机 nonce；HMAC-SHA256 认证标签防篡改/防错密钥。
  块表对密文容器计 sha256（DN 静默损坏/副本一致性链路不变），
  另存 `plain_checksum/plain_size/enc_kid` 供解密后端到端校验与逻辑 Range。
* **读取透明**：NN 取回密文 → 按块头 `kid` 取对应版本密钥 → HMAC 校验 →
  解密；加密块不透传 Range 给 DN（整块取回本地切片）。下载/预览/diff/版本无感。
* **密钥轮换无停机窗口、历史不失效**：每目录一条**只增不删**的密钥版本链
  （存 `crypto.json`，不进 DN 同步白名单，内部接口也拒绝导出）。
  轮换 = 原子追加新版本并切 `current_kid`：旧块头记旧 kid 永远用旧密钥读，
  新写用新密钥；块不可变 ⇒ 不存在"换了密钥读不出"的时刻，
  全部历史提交快照同理永久可读。
* **存量重加密**：启用加密后可把目录内明文/旧密钥块用当前密钥重写；
  被替换且**无任何引用**的旧明文块立即从全部 DN 擦除（不等 GC 宽限期），
  仍被历史提交引用的旧块保留（计数上报），保证历史版本不失效。
* **密钥不明示**：常规接口只返回指纹/版本/用量；查看完整密钥须
  `crypto_admin`（admin）且**再次输入口令 + 填写原因**，每次查看写审计。
* **落盘验证**：`POST /api/crypto/verify` 以集群内部身份直连 DN 读取
  **未经解密**的原始字节，断言：是 DFSENC1 容器、无文件名等明文特征、
  HMAC 通过、解密后内容哈希一致、各副本密文逐字节一致。

---

## 5. REST API 摘要（节选）

```
POST /api/auth/login|logout      GET /api/auth/me|sessions
GET  /api/fs/tree|list|stat      POST /api/fs/mkdir|rename|move|delete
GET  /api/thumbnail|file/preview|file/blocks
POST /api/upload/begin|chunk|complete      GET /api/upload/status|sessions
GET  /api/download/info|download(Range)
GET  /api/version/branches|commits|graph|diff|working_diff|file_at|history|stats
POST /api/version/commit|branch|branch_delete|checkout|merge|restore|diff_text
GET  /api/nodes|nodes/blocks|nodes/matrix|nodes/block_paths
GET  /api/health/queue           GET /api/sim/events
POST /api/sim/kill|revive|corrupt|chaos                （admin）
GET  /api/stats/overview|hotness|timeline
GET|POST /api/users  PUT|DELETE /api/users/<name>      （user_admin）
GET|POST /api/perms  PUT|DELETE /api/perms/<id>        （perm_admin）
POST /api/perms/check
GET  /api/crypto/overview|scope       POST /api/crypto/verify
POST /api/crypto/enable|rotate|reencrypt|reveal        （crypto_admin）
GET  /api/crypto/revels                                （crypto_admin）
GET  /api/logs|logs/export       POST /api/logs/clear  （admin）
GET  /api/recycle                POST /api/recycle/restore|purge|empty
POST /internal/heartbeat|block_report      GET /internal/meta/<doc>   （集群密钥）
```

---

## 6. 目录结构

```
gsb4/
├── run.py                     # 启动入口
├── backend/
│   ├── config.py              # 全部可调参数（块大小/副本/心跳/保留期…）
│   ├── util.py                # 原子写/版本向量/HTTP 客户端/LRU/环形缓冲
│   ├── chunking.py            # 固定 + CDC 分块、清单、重组校验
│   ├── diff_engine.py         # Myers / Patience / merge3 / 渲染器
│   ├── metadata.py            # JSON 文档仓库（原子写 + vv 同步语义）
│   ├── auth.py                # 用户/口令/会话 + 路径 ACL
│   ├── crypto.py              # DFSENC1：HMAC-CTR 封包/解封（仅标准库）
│   ├── keystore.py            # 加密目录 + 密钥版本链/轮换/明文查看审计
│   ├── filesystem.py          # inode 树 + 回收站
│   ├── versioning.py          # 提交/分支/合并/检出/GC 引用集
│   ├── namenode.py            # 块表/放置/心跳/恢复/上传下载/统计/GC/加解密读写
│   ├── datanode.py            # 块存储/心跳/汇报/scrub/流水线/文档同步
│   ├── http_server.py         # 路由 + 静态页 + 鉴权中间件
│   ├── seed.py                # 演示数据（含 /finance 落盘加密 + 轮换场景）
│   └── main.py                # 集群装配
├── frontend/                  # 12 页面（含 crypto.html）+ css/app.css + js/app.js
└── tests/smoke_test.py        # 97 项端到端断言
```

