# UE PCAP Filter - IMSI 关联数据包过滤工具

基于 Go + Vite/React 构建的 Web 应用，通过 tshark 从 PCAP 文件中按 IMSI 关联提取 UE 相关的信令包。

## 功能特性

- **多文件上传合并**：支持上传多个 PCAP 文件，自动合并为一个文件
- **IMSI 自动扫描**：从 PCAP 中提取所有 IMSI（支持 NGAP/PFCP/S1AP/GTPv2/NAS）
- **协议关联过滤**：基于 IMSI 关联 UE 会话标识符（RAN/AMF ID、SEID、TEID 等）
- **多协议支持**：NGAP (5G)、PFCP (5G N4)、S1AP (LTE)、GTPv2-C、GTP-U
- **批量导出**：选择多个 IMSI 批量导出，自动打包为 ZIP

## 系统要求

- Go 1.21+
- Node.js 18+（仅开发时需要）
- **tshark** 和 **mergecap**（Wireshark 工具链）

### 安装 Wireshark 工具链

```bash
# macOS
brew install wireshark

# Ubuntu/Debian
sudo apt install tshark wireshark-common

# CentOS/RHEL
sudo yum install wireshark-cli
```

## 快速开始

### 方式一：直接运行二进制

```bash
# 构建
go build -o uepcap ./cmd/server

# 运行
./uepcap -port 8080 -data ./data -ttl 1h

# 访问 http://localhost:8080
```

### 方式二：开发模式

```bash
# 终端 1：启动后端
go run ./cmd/server -port 8080

# 终端 2：启动前端开发服务器
cd web && npm install && npm run dev

# 访问 http://localhost:5173
```

## 命令行参数

| 参数 | 默认值 | 说明 |
|------|--------|------|
| `-port` | 8080 | HTTP 服务端口 |
| `-data` | ./data | 数据目录（存储临时 PCAP） |
| `-ttl` | 1h | 任务过期时间（自动清理） |

## API 接口

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/jobs` | 上传 PCAP 文件（multipart/form-data, field: files） |
| GET | `/api/jobs` | 列出所有任务 |
| GET | `/api/jobs/{id}` | 获取任务详情 |
| DELETE | `/api/jobs/{id}` | 删除任务 |
| GET | `/api/jobs/{id}/imsis` | 扫描并返回 IMSI 列表 |
| POST | `/api/jobs/{id}/export` | 导出 PCAP（body: {imsis:[], protocols:[]}） |
| GET | `/api/jobs/{id}/download/{filename}` | 下载导出的文件 |

## 协议关联算法

### NGAP (5G N2)

1. 在 `InitialUEMessage (procedureCode=15)` 中通过 MSIN 定位 UE
2. 提取 `RAN-UE-NGAP-ID`
3. 从后续消息中提取 `AMF-UE-NGAP-ID`
4. 使用 `ngap.RAN_UE_NGAP_ID || ngap.AMF_UE_NGAP_ID` 过滤

### PFCP (5G N4)

1. 在 `Session Establishment Request (msg_type=50)` 的 User ID IE 中匹配 IMSI
2. 提取 SMF SEID
3. 从 Response 中提取 UPF SEID
4. 使用 `pfcp.seid` 过滤所有相关消息

### S1AP (LTE)

1. 在 NAS 消息中通过 IMSI 定位
2. 提取 `MME-UE-S1AP-ID` 和 `ENB-UE-S1AP-ID`
3. 使用这些 ID 过滤所有 S1AP 消息

### GTPv2-C / GTP-U

1. 通过 `e212.imsi` 在 GTPv2 协议范围内匹配（`gtpv2.imsi` 不是有效字段）
2. 提取 TEID 用于扩展到 GTP-U

## 项目结构

```
uepcap/
├── cmd/server/          # Go 主程序入口
│   ├── main.go
│   └── dist/            # 前端构建输出（嵌入到二进制）
├── internal/
│   ├── api/             # HTTP API handlers
│   ├── job/             # 任务管理（内存索引）
│   ├── pcap/            # PCAP 工具函数
│   ├── protocol/        # 协议解析器（IMSI 扫描 + Filter 解析）
│   └── tshark/          # tshark/mergecap 命令封装
├── web/                 # Vite + React 前端源码
│   ├── src/
│   │   ├── components/  # React 组件
│   │   └── App.tsx
│   └── package.json
├── data/tmp/            # 临时文件目录（运行时生成）
└── go.mod
```

## 注意事项

1. **tshark 字段大小写**：NGAP 字段必须大写（如 `ngap.AMF_UE_NGAP_ID`）
2. **无外部数据库**：所有状态存储在内存中，重启后任务数据丢失
3. **TTL 自动清理**：超过 TTL 的任务会被自动删除
4. **加密 NAS**：Security Mode Complete 后的 NAS 消息可能已加密，无法解析 IMSI

## License

MIT
