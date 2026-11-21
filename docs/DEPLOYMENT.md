# 部署与运维指南（DEPLOYMENT）

> 适用范围：本仓库当前开发版（版本 0.1.7）。部署形态为单机 Docker Compose + 只读挂载 NAS 目录。
>
> 安全边界请先阅读 [SECURITY-NOTES.md](SECURITY-NOTES.md)（精简版）或 [SECURITY.md](../SECURITY.md)（完整版）；常见问题见 [FAQ.md](FAQ.md)。

---

## 1. 前置条件

| 项目 | 要求 |
|---|---|
| 主机 | Linux（x86_64 / arm64），Docker Engine 24+，Docker Compose v2 |
| 扫描目录 | NAS 或本地目录在宿主机上的**绝对路径**，运行容器所用 UID/GID 具备读 + 执行权限（`r-x`） |
| 端口 | 默认 `8080`，可通过 `HOST_PORT` 修改；不要直接暴露到公网 |
| 磁盘 | 仓库下 `./data`（数据库、导出、日志），容量随文件数量增长 |
| NAS 写权限 | **不需要**。容器以只读方式挂载扫描目录，启动和运行期都会验证 |

本工具不要求、也不应该获得 NAS 的写权限。

---

## 2. 获取代码与准备目录

```bash
git clone <仓库地址> dupe-checker
cd dupe-checker
```

仓库中与本指南相关的文件：

- `docker-compose.yml`：默认单根部署；
- `compose.multiroot.example.yaml`：多根只读挂载示例；
- `.env.example`：环境变量模板；
- `docs/FAQ.md`、`docs/SECURITY-NOTES.md`：常见问题与安全边界。

---

## 3. 配置 `.env`

```bash
cp .env.example .env
```

按实际情况修改：

| 变量 | 默认 | 说明 |
|---|---|---|
| `SCAN_ROOT` | 必填 | 要扫描的宿主机绝对路径，例如 `/vol1/1000/我的图库`；**不能为空**，且必须是已存在目录 |
| `APP_UID` / `APP_GID` | `1001` / `1001` | 容器运行身份，必须对 `SCAN_ROOT` 有读 + 执行权限；模板默认 `1001:1001`，compose 未设置时回退 `1000:1000`；普通 Linux 常见 `1000:1000`，飞牛等 NAS 常见 `1001:1001` |
| `HOST_PORT` | `8080` | 宿主机端口 |
| `BIND_ADDR` | `0.0.0.0` | 监听地址；只本机反代时建议 `127.0.0.1` |
| `TZ` | `Asia/Shanghai` | 时区，影响日志时间和扫描计划 |
| `AUTH_MODE` | `password` | `password` 口令登录；`none` 免登录（仅可信内网） |
| `SESSION_TTL_SECONDS` | `28800` | 登录会话有效期（8 小时） |
| `SESSION_COOKIE_SECURE` | `auto` | `auto`/`always`/`never`；HTTPS 反代建议 `always` |
| `GUARD_INTERVAL_SECONDS` | `1800` | 只读自检复查间隔（30 分钟） |
| `DUPE_SETUP_TOKEN` | 空 | 可选，指定首次初始化令牌（自动化部署用）；不设置则自动生成随机令牌 |

示例（请替换为你的真实路径与 UID/GID）：

```dotenv
SCAN_ROOT=/vol1/1000/我的图库
APP_UID=1001
APP_GID=1001
HOST_PORT=8080
BIND_ADDR=0.0.0.0
TZ=Asia/Shanghai
AUTH_MODE=password
SESSION_COOKIE_SECURE=auto
```

准备数据目录，并确保容器运行身份可写：

```bash
mkdir -p data
sudo chown -R 1001:1001 data
```

> `APP_UID`/`APP_GID` 与 `chown` 的数字要一致；否则会因无法写数据库/日志而启动失败。

---

## 4. 启动

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f --tail=100 dupe-checker
```

启动时的只读自检（guard 失败会以退出码 2 拒绝启动）：

1. `MOUNT_ROOTS` 非空；
2. 每个扫描根在宿主机存在、是目录、运行账号可读；
3. 对扫描根做**写探测**：能创建文件即判定可写，拒绝启动；`EACCES`/`EPERM`/`EROFS` 视为只读通过；
4. 向下抽样最多 20 个子目录、深度不超过 3，重复写探测。

另外，启动还会创建/校验 `./data` 下的数据库、导出、日志目录；若不可写会直接启动失败（通常是异常退出，不一定是退出码 2），请检查 `data` 属主与权限。

健康检查：

```bash
curl -fsS http://127.0.0.1:8080/health
```

`/health` 为匿名接口，正常返回 `status: ok`（不含敏感信息）。

---

## 5. 首次初始化（`AUTH_MODE=password`）

首次启动会生成一次性初始化令牌。获取方式（任选其一）：

1. **容器日志**（推荐）：

   ```bash
   docker compose logs dupe-checker | grep -A2 "setup token"
   ```

   日志中会打印“首次启动：初始化令牌（setup token）”横幅，下一行即为令牌。

2. **环境变量**：启动前在 `.env` 设置 `DUPE_SETUP_TOKEN=<你的令牌>`。该值优先于自动生成，并会同步写入 `data/setup_token`。

3. **令牌文件**：`data/setup_token`（权限 `0600`，归 `APP_UID` 所有）。宿主机上可用 `sudo cat data/setup_token` 读取。

然后：

1. 浏览器打开 `http://<主机IP>:8080/setup`（可加 `?token=<令牌>` 预填）；
2. 输入令牌，设置管理员口令：**至少 10 位**，最长 200 位，使用 bcrypt 存储；
3. 提交成功后令牌文件自动删除，`/setup` 再次访问会被拒绝；
4. 之后通过 `/login` 登录。

> `AUTH_MODE=none` 时跳过初始化令牌和口令，直接访问页面即可（见第 6 节）。

**忘记口令怎么办？** 当前版本没有在线找回/重置口令功能：

- 有备份：停止容器，按第 10 节从备份恢复 `./data`；
- 无备份：停止容器，把 `./data` 移到别处（例如 `data.bak`），重新启动后会生成新的初始化令牌并重建数据库。此操作会丢失索引、审核记录和日志，但**不会影响 NAS 上的文件**。

---

## 6. 认证模式

| 模式 | 行为 | 适用场景 |
|---|---|---|
| `password`（默认） | 首次 `/setup` 设置口令，之后 `/login`；会话 Cookie 8 小时；写请求需要 CSRF Token | 任何真实使用场景 |
| `none` | 免登录；仍签发 CSRF 会话；任何能访问端口的人可查看清单、触发扫描、导出 | 仅完全可信的内网、临时本机调试 |

两种模式都**不会**增加删除/写入能力：工具本身没有删除接口。不要把 `none` 模式暴露到公网，也不要在公网反代后使用。

---

## 7. 多目录只读挂载

单根不够时，用多根示例叠加：

```bash
cp compose.multiroot.example.yaml compose.multiroot.yaml
# 编辑 compose.multiroot.yaml：MOUNT_ROOTS 与 volumes 一一对应
docker compose -f docker-compose.yml -f compose.multiroot.yaml up -d
```

规则：

- `MOUNT_ROOTS` 用**英文逗号**分隔多个绝对路径；
- 每个根在 `volumes` 中写一条 `宿主机绝对路径:容器内相同绝对路径:ro`；
- 容器内路径保持与宿主机一致，索引和导出中的路径才可直接在 NAS 上核对；
- 每个根都必须对 `APP_UID`/`APP_GID` 可读；
- 每个根都会在启动和运行期被写探测，任何一个根可写都会导致启动失败或进入 unsafe；
- 路径含空格时在 YAML 中用引号包裹，并确认 `MOUNT_ROOTS` 逗号分隔解析正确（路径本身不要含逗号）。

只想扫描某个子目录时，把该子目录作为一个独立根挂载即可，不需要挂载整个共享目录。

---

## 8. 反向代理与 HTTPS（可选）

建议由**宿主机上的** Nginx/Caddy 终止 TLS，再转发到 `127.0.0.1:8080`。应用只信任来自回环地址的 `X-Forwarded-Proto`；若代理在另一个容器中，转发头不会被信任，此时应直接使用 HTTPS 端口或显式设置 `SESSION_COOKIE_SECURE=always`。

`.env` 建议：

```dotenv
BIND_ADDR=127.0.0.1
SESSION_COOKIE_SECURE=always
```

Nginx 示例：

```nginx
server {
    listen 443 ssl;
    server_name dupe.example.com;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 3600s;
    }
}
```

注意：

- 仅允许可信来源访问；不要做公网匿名开放；
- 扫描/导出可能耗时较长，适当放宽代理读超时；
- 使用 `AUTH_MODE=none` 时不要放在公网反代后面。

---

## 9. 升级

1. 阅读版本说明，确认配置/数据库变更；
2. **先备份 `./data`**（见第 10 节）；
3. 拉取新代码：

   ```bash
   git pull
   ```

4. 重新构建并启动：

   ```bash
   docker compose up -d --build
   ```

5. 查看日志与健康状态：

   ```bash
   docker compose logs --tail=100 dupe-checker
   curl -fsS http://127.0.0.1:8080/health
   ```

6. 登录后抽查目录、扫描、审核页面。

数据库会在启动时按 `schema_version` 做轻量迁移（当前 `schema_version=1`），但仍必须先备份。**不保证可降级**：回退旧版本前应先恢复对应备份。

---

## 10. 备份与恢复

需要备份的只有 `./data`（NAS 上的文件工具不会修改，不需要备份）：

- `data/db/dupe.db`：索引、审核、方案、设置；
- `data/exports/`：导出清单；
- `data/logs/`：日志；
- `data/setup_token`：仅初始化前存在。

**备份**（建议停容器保证数据库一致）：

```bash
docker compose stop
sudo tar -C . -czf "dupe-data-$(date +%F).tgz" data
docker compose start
```

**恢复**：

```bash
docker compose down
sudo mv data data.broken
sudo tar -C . -xzf dupe-data-2026-11-22.tgz
sudo chown -R 1001:1001 data
docker compose up -d
```

保持 `data` 的属主与 `APP_UID`/`APP_GID` 一致，否则容器无法写数据库和日志。恢复后按原 `AUTH_MODE`/口令登录；若备份来自旧版本，启动时会执行轻量迁移。

---

## 11. 停止与卸载

```bash
# 停止但保留数据
docker compose stop

# 停止并删除容器/网络（./data 保留）
docker compose down
```

彻底清理：

```bash
docker compose down
rm -rf ./data
```

`docker compose down -v` 不会删除宿主机上的 `./data`（未使用命名卷）。NAS 上的文件始终不受影响；已导出的清单如需保留请先复制出去。

---

## 12. 常见故障排查

| 现象 | 可能原因 | 处理 |
|---|---|---|
| 容器启动即退出，退出码 2 | `MOUNT_ROOTS` 为空；扫描根不存在/不是目录/不可读；扫描根**可写**；嵌套子目录可写 | 看 `docker compose logs` 的 guard 日志；修正挂载为 `:ro`；确认 UID/GID 权限；重新启动 |
| 启动异常退出但非退出码 2 | `./data` 不可写、数据库初始化失败等 | 检查 `data` 属主与权限（与 `APP_UID`/`APP_GID` 一致）；看日志异常 |
| 运行中扫描/生成方案/导出返回 409 `GUARD_UNSAFE` | 运行期复查发现扫描根变成可写 | 恢复只读挂载；等待 `GUARD_INTERVAL_SECONDS` 复查或重启容器 |
| 找不到初始化令牌 | 日志被清理；已初始化（令牌已删）；`AUTH_MODE=none` | 首次启动前设置 `DUPE_SETUP_TOKEN`；已初始化则用 `/login`；确认模式 |
| 访问页面 401 | 会话过期（默认 8 小时）或未登录 | 重新访问 `/login` |
| 写操作 403 CSRF | 页面过期或直接调用接口未带 `X-CSRF-Token` | 刷新页面后重试；API 调用先获取会话与 CSRF Token |
| 403 `FORBIDDEN_PATH` | 目录无读权限或路径不可访问 | 检查 NAS 权限与容器 UID/GID |
| 404 `NOT_FOUND` | 根/方案/清单不存在，或已删除 | 刷新页面确认对象仍存在 |
| 登录返回 429 | 登录失败限流（默认 5 次/分钟/IP） | 等待 1 分钟后重试；确认口令 |
| 导出被 409 拒绝 | 清单不是 final；或复核发现文件变化/保留份缺失 | 在清单页“重新校验”；必要时重新扫描、重新生成方案 |
| 扫描 409 | 已有扫描在运行，或 guard unsafe | 等待当前扫描结束；检查 guard 状态 |
| 页面打不开/连接被拒 | 端口被占用、`BIND_ADDR` 限制、容器未启动 | 改 `HOST_PORT`；`docker compose ps`/`logs`；`ss -ltnp` 查端口 |
| 时间不对/计划不执行 | `TZ` 未设置 | 设置 `TZ=Asia/Shanghai`（或你的时区）并重启 |
| 健康检查 unhealthy | 应用未就绪/内部错误 | 看日志与 `/health`；确认数据库目录可写 |
| CSV 乱码 | Excel 未按 UTF-8 解析 | 用“数据 → 从文本/CSV”选择 UTF-8；首行 `#` 是说明不是表头 |

更多使用层问题见 [FAQ.md](FAQ.md)。

---

## 13. 部署验收检查清单

- [ ] `docker compose ps` 显示容器 running，健康检查通过；
- [ ] `/health` 返回 `status: ok`；
- [ ] 扫描根均为 `:ro` 挂载，启动日志没有 guard 失败；
- [ ] 能登录（或按预期 `AUTH_MODE=none` 免登录），能看到已启用的根；
- [ ] 小范围扫描可完成，审核、生成方案、导出流程可走通；
- [ ] 重启容器后索引/审核记录仍在（`./data` 持久化正常）；
- [ ] 已做一次 `./data` 备份并验证可恢复；
- [ ] 如使用反代：HTTPS 正常，`SESSION_COOKIE_SECURE` 与 `BIND_ADDR` 符合预期；
- [ ] 端口未暴露到公网，`AUTH_MODE` 与使用场景匹配。

---

## 14. 已知限制与计划项

- 单用户、单实例部署；不支持多租户或集群；
- 不做定时备份，备份需自行安排；
- 没有在线口令重置；忘记口令只能恢复备份或重建 `./data`；
- 审核列表按目录/扩展名筛选、目录树逐层下钻、`test-globs` 规则预览等为**计划中**，尚未实现；
- 升级不保证可降级，回退需恢复旧版本对应的 `./data` 备份。
