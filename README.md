# dupe-checker

> 面向 NAS 的**只读**重复文件核查工具：找出重复，交给人来删。

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![status](https://img.shields.io/badge/status-development--iter2-orange)

## 这是什么

NAS 用久了，同一张照片、同一份备份经常存在好几份，悄悄吃掉存储空间。
dupe-checker 扫描你指定的目录，找出两类对象：

- **同名候选**：文件名相同（可能内容也相同，也可能不同）
- **内容重复**：文件大小相同，且全文件 SHA-256 一致

然后在浏览器里逐组审核：看路径、大小、修改时间、哈希，决定保留哪一份。
最后导出一份带指纹的**删除方案**，由你**自己在 NAS 上手工删除**。

## 安全承诺（最重要）

- **只读**：目标目录以只读方式挂载；容器启动时做写探测自检（含嵌套子目录抽样），运行期每 30 分钟复查，一旦发现可写立刻停用扫描与导出（接口返回 409）。
- **不删除**：工具不提供任何删除/移动/改名/写入用户文件的接口。
- **受限身份运行**：以受限制的 NAS 账号运行（非 root、无 sudo），权限只到授权目录的只读。
- **不越权**：只扫描你显式选择、且运行账号有读权限的目录。
- **不输出命令**：删除方案只给文件路径清单，不生成 rm 等可执行命令。
- **每组至少保留 1 份**：系统层面禁止生成"整组删除"的方案。
- **删除前复核**：生成方案时重新校验大小/修改时间/SHA-256，文件变了就标"需复核"。
- **只导出可复核的方案**：方案状态不是「通过复核」时禁止导出（HTTP 409），导出前还会再核对 keep 文件未被改动。
- **首启防护**：首次设置口令需要一次性初始化令牌（从容器日志获取），避免同网段他人抢占初始化。
- **数据不外传**：无遥测、无云调用；索引与方案只存在本地卷。

一句话：**找重复靠工具，删文件靠人**。

## 功能

- [x] Docker Compose 单镜像部署，兼容飞牛 fnOS 与普通 Linux
- [x] 自选扫描目录（多套扫描方案、包含/排除规则）
- [x] 扫描默认关闭；支持手动 / 每日 / 每周 / 自定义间隔 / 仅提醒
- [x] 三级判定：大小 → 采样快哈希 → 全量 SHA-256（带哈希缓存）
- [x] 增量扫描、断点续扫、限速与低优先级
- [x] 双视图审核：同名候选 / 内容重复（默认保留 mtime 最早的一份）
- [x] 删除方案导出 JSON / CSV / HTML（含指纹与复核状态）
- [ ] fnOS 应用包（.fpk）封装：先跑通 Compose，再上架形态（规划中）
- [ ] 缩略图预览：v1 不提供（会读图片内容、增加权限面），规划中

## 状态

项目按企业七阶段流程推进，当前：**开发编码（阶段 4/7）**。
代码已实现并通过 **94 项自动化测试（覆盖率 80%）**，独立代码评审提出的 P0/P1 问题已全部修复，并在飞牛 fnOS 真机上完成安全回归（初始化令牌、违规回滚、同名不同内容拦截、非终态方案拒导全部通过）。真机体验与性能压测在 NAS 上进行。

## 关于本项目：由 AI 开发

> **本项目的需求分析、架构设计、编码、测试与文档，全部由 AI 交付代理完成**（AI coding agent，基于 DeepSeek Harness 运行）。
>
> 项目发起人 / 需求方：**多拉贡**（GitHub [@3796525](https://github.com/3796525)），负责提出需求、提供测试环境、审核与验收。
>
> 发起人并非专业软件工程师（他自嘲"菜鸡"），因此本项目的技术设计、代码质量与取舍**由 AI 负责**。如果你发现设计缺陷、安全问题或可以改进的地方，那多半是 AI 的锅——欢迎提 Issue 指正，我们会认真修。

- 作者与分工：见 [AUTHORS.md](AUTHORS.md)
- 安全问题报告：见 [SECURITY.md](SECURITY.md)

## 快速开始（Docker Compose）

    git clone https://github.com/3796525/dupe-checker.git
    cd dupe-checker
    cp .env.example .env

编辑 `.env`，至少改两项：

- `SCAN_ROOT`：要扫描的绝对路径。**必须以运行容器的账号可读为前提**，容器会以 `:ro` 只读挂载它。
- `APP_UID` / `APP_GID`：容器运行身份，要等于 `SCAN_ROOT` 的读权限持有者（飞牛功能受限账号 dsh-test 是 `1001:1001`，普通 Linux 通常是 `1000:1000`）。

准备数据目录（索引、导出、会话都放这里，也是容器唯一可写的位置）：

    mkdir -p data && sudo chown -R 1001:1001 data   # 换成你的 APP_UID:APP_GID

启动：

    docker compose up -d --build
    docker compose ps          # 等待 healthy

    # 首次启动需要一次性初始化令牌，从容器日志读取：
    docker compose logs dupe-checker | grep -A2 "setup token"

    # 浏览器打开 http://<NAS 或笔记本 IP>:8080 ，进入 /setup
    # 输入初始化令牌 + 访问密码（至少 10 位，bcrypt 存储），设置完成即进入系统

说明：初始化令牌只在首次设置口令前有效，设置成功后自动删除；若容器日志不便查看，可在 `.env` 里设置 `DUPE_SETUP_TOKEN` 指定自己的令牌。

扫描多个目录：

    docker compose -f docker-compose.yml -f compose.multiroot.example.yaml up -d

### 使用流程

1. **扫描根**：确认容器启动自检通过（页面顶部会显示只读自检状态）。
2. **扫描方案**：选目录、可加包含/排除规则、选触发方式（仅手动 / 每日 / 每周 / 间隔 / 仅提醒）。
3. **执行扫描**：点「立即扫描」，扫描中可暂停/继续/取消；扫描结束自动生成审核分组。
4. **审核**：在「内容重复」或「同名候选」里逐组决定保留/删除，每组必须至少保留 1 份。
5. **生成删除方案**：工具会重新核对每个待删文件的大小、mtime、SHA-256，变化过的标为「需复核」。
6. **导出 + 手工删除**：下载 CSV / JSON / HTML，按路径自己在 NAS 上删除；工具不提供删除按钮，也不生成 rm 命令。

### 目录结构

    app/             FastAPI 应用（扫描、审核、方案、导出、Web）
    app/templates/   Jinja2 页面
    app/static/      CSS / JS
    tests/           pytest 测试（94 项，覆盖率 80%）
    docs/            需求、设计、开发说明等项目文档
    main.py          启动入口
    docker-compose.yml / Dockerfile / .env.example

### 开发（本机跑测试）

    python3.11 -m venv .venv && . .venv/bin/activate
    pip install -r requirements-dev.txt
    python -m pytest

### 安全边界（部署前请确认）

- `SCAN_ROOT` 必须用 `:ro` 挂载；写成可写会在启动自检阶段被拒绝启动。
- 端口只在内网开放，不要做公网端口映射。
- 容器 rootfs 只读、capabilities 全丢、`no-new-privileges`。
- 会话默认 8 小时过期，注销会服务端吊销旧会话；会话 cookie 在内网 HTTP 下不加 Secure，走反代/TLS 时设 `SESSION_COOKIE_SECURE=always`。
- 首启未设置口令前，任何未携带初始化令牌的 `/setup` 请求都会被拒绝（403），不会暴露"是否已初始化"。

## 许可

[MIT](LICENSE) © 2026 多拉贡
