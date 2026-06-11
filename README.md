# UE PCAP Filter

UE PCAP Filter 是一个面向移动核心网抓包分析的 Web 工具。它可以从 PCAP/PCAPNG 中扫描 IMSI/SUPI/SUCI，自动关联 NGAP、PFCP、S1AP、GTPv2-C、GTP-U、NAS 等协议标识，生成过滤后的抓包、流程图、消息统计和协议事务分析结果。

项目同时提供：

- Web UI：上传、扫描、导出、流程查看、统计分析、协议分析、包结构对比。
- HTTP API：可被其他系统集成。
- Go SDK：可作为 `gitee.com/yangdadayyds/uepcap` 包嵌入。
- MCP Server：供大模型客户端直接调用 PCAP 分析能力。

---

## 一键部署

推荐使用 Docker Compose。用户拉取仓库后，宿主机只需要 Docker/Compose；Go、Node.js、tshark、mergecap 都在镜像构建或运行环境中处理。

```bash
git clone <repository-url>
cd uepcap
cp .env.example .env   # 可选：修改端口、TTL、清理周期等配置
make deploy
```

访问：

```text
http://localhost:8080
```

服务器部署时把 `localhost` 换成服务器 IP。端口可在 `.env` 中通过 `UEPCAP_PORT` 修改。

常用运维命令：

```bash
make ps      # 查看容器状态
make logs    # 查看服务日志
make stop    # 停止服务但保留 data 目录
make reset   # 停止服务并清空运行数据
```

不用 `make` 时也可以直接运行：

```bash
docker compose up -d --build
docker compose down --remove-orphans
```

旧版 Compose 环境可把 `docker compose` 替换为 `docker-compose`。

### 环境变量

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `UEPCAP_PORT` | `8080` | 宿主机访问端口 |
| `UEPCAP_TTL` | `1h` | 运行中 Job 的 TTL |
| `UEPCAP_MAX_JOBS` | `20` | 内存中最多保留 Job 数，`0` 表示不限制 |
| `UEPCAP_MAX_TSHARK` | `0` | 并发 tshark/mergecap 数量，`0` 表示自动 |
| `UEPCAP_RETENTION_DAYS` | `2` | 清理容器删除超过多少天的 `data/tmp` 目录 |
| `UEPCAP_CLEANUP_INTERVAL_SECONDS` | `86400` | 清理容器检查间隔 |
| `TZ` | `Asia/Shanghai` | 容器时区 |

运行数据挂载在仓库的 `./data`，其中 `data/tmp/{job_id}` 存放上传、合并和导出文件。`make reset` 会删除运行数据。

---

## 功能概览

### 上传与历史记录

- 支持上传单个或多个 `.pcap` / `.pcapng` 文件。
- 多文件上传会自动使用 `mergecap` 合并。
- 保留服务端使用记录，支持重新打开最近任务、删除单条记录、清空记录。
- 浏览器侧保留最近导入记录，便于快速回到常用抓包。

### IMSI 扫描与 UE 关联

- 支持 NGAP、PFCP、S1AP、GTPv2-C、NAS 等多协议 IMSI/SUPI/SUCI 扫描。
- 支持流式扫描，前端实时显示结果。
- 通过 RAN/AMF UE NGAP ID、S1AP UE ID、SEID、TEID、UE IP 等标识生成 Wireshark display filter。
- 可按 IMSI 和协议导出过滤后的 PCAP。
- 可导出结构化 JSON 文本，供流程图、外部工具或大模型分析使用。

### 消息统计

- 统计 NAS、SM NAS、NGAP、S1AP、S11/GTPv2、PFCP 消息类型。
- 支持流式统计、暂停/继续、重新统计。
- 支持 Excel 下载。
- NGAP 统计已覆盖切换相关消息，包括 Handover Preparation、Handover Resource Allocation、Path Switch、RAN Status Transfer 等。

### 协议分析面板

- NGAP：过程统计、事务配对、方向推断、NAS 承载标记、切换事务分析。
- S1AP：过程统计、事务配对、切换/上下文/承载流程分析。
- NAS MM：注册、服务、鉴权、安全、身份等流程分析。
- SM NAS：PDU Session 建立、修改、释放等会话管理分析。
- S11/GTPv2：请求响应事务、失败/超时、响应时间分析。
- PFCP Session：会话建立、修改、删除、上报事务分析。
- 大抓包分析使用分批流式返回，降低内存峰值并保持页面可响应。

### 流程与包结构

- 自动推断 IP 到网元角色，例如 AMF/gNB、MME/eNB、SMF/UPF、SGW/PGW。
- 生成 UE 维度的信令流程摘要和 Mermaid 时序图。
- 支持按帧查看协议树详情。
- 支持双抓包消息结构对比，以及粘贴协议树文本进行对比。

### 稳定性与性能

- 上传、扫描、导出、统计和协议分析均有缓存或流式路径。
- 支持限制并发 tshark/mergecap 进程，避免大抓包压垮主机。
- 长耗时分析提供进度、暂停/恢复和重新执行入口。
- Docker 日志默认按大小轮转，清理容器会定期清理历史临时目录。

---

## Web 使用流程

1. 打开 `http://localhost:8080`。
2. 上传一个或多个 PCAP 文件。
3. 点击“开始扫描 IMSI”。
4. 选择目标 IMSI 和协议范围。
5. 执行导出，下载过滤后的 PCAP 或 JSON 文本。
6. 使用消息统计、NGAP/S1AP/NAS/S11/PFCP 分析面板查看事务和异常。
7. 需要排查差异时，进入包对比视图进行双抓包或协议树对比。

---

## 常用命令

| 命令 | 说明 |
| --- | --- |
| `make deploy` | Docker 一键构建并后台运行 |
| `make stop` | 停止 Docker Compose 服务，保留本地数据 |
| `make reset` | 停止 Docker Compose 服务并清空运行数据 |
| `make logs` | 查看 Docker 服务日志 |
| `make ps` | 查看 Docker 服务状态 |
| `make run` | 在宿主机源码构建并运行服务 |
| `make dev` | 开发模式运行后端 |
| `make build` | 构建前端和后端 |
| `make build-mcp` | 构建 MCP server |
| `make run-mcp` | 运行 MCP server（stdio） |
| `make test` | 运行 Go 测试 |
| `make clean` | 清理构建产物和临时文件 |
| `make check-deps` | 检查源码运行依赖 |

---

## 源码运行与开发

Docker 部署不需要宿主机安装以下依赖。只有源码运行或开发时才需要：

| 依赖 | 版本要求 | 说明 |
| --- | --- | --- |
| Go | 1.24.3+ | 后端和 SDK 构建 |
| Node.js | 18+ | 前端构建 |
| npm | 随 Node.js 安装 | 前端包管理 |
| tshark | 3.0+ | PCAP 解析 |
| mergecap | 3.0+ | PCAP 合并，随 Wireshark 安装 |

源码运行：

```bash
make run
```

开发模式：

```bash
# 终端 1：后端
make dev

# 终端 2：前端
cd web
npm install
npm run dev
```

前端开发服务器为 `http://localhost:5173`，会代理 `/api` 到后端 `http://localhost:8080`。

---

## HTTP API

所有 API 返回统一结构：

```json
{
  "success": true,
  "data": {}
}
```

常用路由：

| 方法 | 路由 | 说明 |
| --- | --- | --- |
| `POST` | `/api/jobs` | 上传 PCAP，创建 Job |
| `GET` | `/api/jobs` | 列出当前 Job |
| `GET` | `/api/jobs/{id}` | 获取 Job 详情 |
| `DELETE` | `/api/jobs/{id}` | 删除 Job |
| `GET` | `/api/usage-records` | 列出使用记录 |
| `DELETE` | `/api/usage-records` | 清空使用记录 |
| `DELETE` | `/api/usage-records/{id}` | 删除一条使用记录 |
| `GET` | `/api/jobs/{id}/imsis` | 扫描 IMSI（普通返回） |
| `GET` | `/api/jobs/{id}/imsis/stream` | 流式扫描 IMSI |
| `POST` | `/api/jobs/{id}/export` | 按 IMSI/协议导出 PCAP |
| `GET` | `/api/jobs/{id}/export/{taskId}/status` | 查询导出状态 |
| `GET` | `/api/jobs/{id}/download/{filename}` | 下载导出文件 |
| `POST` | `/api/jobs/{id}/export/text` | 导出结构化 JSON 文本 |
| `POST` | `/api/jobs/{id}/export/text/download` | 下载结构化 JSON 文本 |
| `POST` | `/api/jobs/{id}/message-stats/stream` | 流式消息统计 |
| `POST` | `/api/jobs/{id}/ngap-messages/stream` | 流式 NGAP 分析 |
| `POST` | `/api/jobs/{id}/s1ap-messages/stream` | 流式 S1AP 分析 |
| `POST` | `/api/jobs/{id}/nas-messages/stream` | 流式 NAS MM 分析 |
| `POST` | `/api/jobs/{id}/sm-nas-messages/stream` | 流式 SM NAS 分析 |
| `POST` | `/api/jobs/{id}/s11-messages/stream` | 流式 S11/GTPv2 分析 |
| `POST` | `/api/jobs/{id}/pfcp-sessions/stream` | 流式 PFCP 会话事务分析 |
| `POST` | `/api/jobs/{id}/flow/brief` | 获取流程摘要 |
| `POST` | `/api/jobs/{id}/flow/generate/stream` | 流式生成 Mermaid 流程 |
| `GET` | `/api/jobs/{id}/packets/{frame}/tree?proto=ngap` | 获取指定帧协议树 |

非流式分析接口也保留，例如 `/message-stats`、`/ngap-messages`、`/s1ap-messages`、`/nas-messages`、`/sm-nas-messages`、`/s11-messages`、`/pfcp-sessions`、`/flow/generate`。

---

## Go SDK

安装：

```bash
go get gitee.com/yangdadayyds/uepcap
```

使用 SDK 时，运行环境需要能访问 `tshark` 和 `mergecap`。Docker Web 部署不需要在宿主机额外安装它们。

### 嵌入 HTTP API

```go
package main

import (
	"context"
	"net/http"
	"time"

	uepcap "gitee.com/yangdadayyds/uepcap"
	"gitee.com/yangdadayyds/uepcap/httpapi"
)

func main() {
	handler, err := httpapi.New(uepcap.Config{
		DataDir: "./data",
		JobTTL:  time.Hour,
		MaxJobs: 5,
	})
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	handler.Start(ctx)

	mux := http.NewServeMux()
	handler.RegisterRoutes(mux)

	_ = http.ListenAndServe(":8080", mux)
}
```

### 程序化调用

```go
app, err := uepcap.New(uepcap.Config{DataDir: "./data"})
if err != nil {
	panic(err)
}

imsis, err := app.ScanIMSIs(context.Background(), "sample.pcap")
if err != nil {
	panic(err)
}

filters, combined, err := app.ResolveFilters(
	context.Background(),
	"sample.pcap",
	imsis[0],
	[]string{"ngap", "pfcp", "s1ap", "gtpv2", "gtpu"},
)
if err != nil {
	panic(err)
}

_ = filters
_ = combined
```

### SDK 配置

| 配置项 | 默认值 | 说明 |
| --- | --- | --- |
| `DataDir` | `./data` | 临时数据目录 |
| `JobTTL` | `1h` | Job 自动清理时间 |
| `MaxJobs` | `3` | 最大保留 Job 数，`0` 表示不限制 |
| `CleanupInterval` | `5m` | 清理任务检查间隔 |
| `TsharkPath` | `tshark` | tshark 可执行文件路径 |
| `MergecapPath` | `mergecap` | mergecap 可执行文件路径 |
| `SkipDependencyCheck` | `false` | 跳过启动依赖检查 |
| `Moonshot` | 环境变量 | 可选，用于流程注释；也可设置 `MOONSHOT_API_KEY`、`MOONSHOT_BASE_URL`、`MOONSHOT_MODEL` |

---

## MCP Server

MCP Server 可以让 Claude Desktop、Cursor 等客户端直接调用 UEPCAP 分析能力。

构建：

```bash
make install-mcp
```

查看配置示例：

```bash
make mcp-config
```

工具列表：

| 工具 | 说明 |
| --- | --- |
| `uepcap_list_pcaps` | 列出 `data/tmp` 下可用 PCAP |
| `uepcap_list_imsis` | 扫描 PCAP 中的 IMSI |
| `uepcap_imsi_brief` | 根据 IMSI 返回协议过滤器、combined filter、UE IP 和简化包数据 |

手动运行：

```bash
./uepcap-mcp --data-dir ./data
```

---

## 项目结构

```text
.
├── cmd/server/              # Web 服务入口，内嵌前端 dist
├── cmd/mcp/                 # MCP server
├── httpapi/                 # 可嵌入 HTTP API
├── internal/api/            # REST/SSE API
├── internal/protocol/       # IMSI 扫描和协议过滤器解析
├── internal/statistics/     # 消息统计
├── internal/ngapanalyzer/   # NGAP 分析
├── internal/s1apanalyzer/   # S1AP 分析
├── internal/nasanalyzer/    # NAS/SM NAS 分析
├── internal/s11analyzer/    # S11/GTPv2 分析
├── internal/pfcpsession/    # PFCP 会话事务分析
├── internal/tshark/         # tshark/mergecap 封装
├── web/                     # React + Vite 前端
├── Dockerfile
├── docker-compose.yml
└── Makefile
```

---

## 排障

### 端口被占用

修改 `.env`：

```bash
UEPCAP_PORT=18080
```

然后重新部署：

```bash
make deploy
```

### Docker Compose 命令不可用

优先安装 Docker Compose v2。若环境只有旧版 `docker-compose`，`Makefile` 会自动兼容。

### 源码运行提示 tshark/mergecap 不存在

源码运行需要宿主机安装 Wireshark CLI：

```bash
# Ubuntu/Debian
sudo apt-get update && sudo apt-get install -y tshark

# macOS
brew install wireshark
```

### 清空所有运行数据

```bash
make reset
```

该命令会停止容器并删除 `data/tmp` 与 `data/usage_records.json`。

---

## License

MIT
