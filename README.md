# esp32s3-adblock

一个跑在 **ESP32-S3** 上的 Pi-hole 式 DNS 广告拦截器，移植自
[M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock)（MIT）。

核心思路不变：**拦截名单以排好序的 40-bit 哈希存放在 flash 里**，用两级索引 +
二分查找匹配，因此**不需要 PSRAM**，也几乎不占 RAM。S3 的 16 MB flash 让它能装下
比 C3 多得多的域名（默认配置约 200 万条）。

```
查询到达 ──▶ 提取域名 ──▶ FNV-1a 哈希（连同各级父域）
          ──▶ 在 flash 哈希表中二分查找
               ├─ 命中 ──▶ 应答 0.0.0.0（黑洞）
               └─ 未命中 ─▶ 转发给上游 DNS，原样回传
```

## 相对于 C3 原版的改动

| 项目 | C3 原版 | 本 S3 版 |
|---|---|---|
| 目标板 / flash | 4 MB | **16 / 8 / 4 MB 三套配置** |
| 平台包 | GitHub release 直链的 pioarduino | **PlatformIO 官方 registry**（国内可下） |
| 保留分区 | app0/app1 各 1.3 MB | **app0/app1 各 3 MB + 9.9 MB LittleFS** |
| 索引规模 | 4096 × 256 ≈ 100 万条 | **8192 × 256 ≈ 200 万条** |
| PSRAM | 无 | 有也不使用（代码零依赖） |
| 上游 DNS 默认 | Quad9 9.9.9.9 | **AliDNS 223.5.5.5**（Quad9 在国内不可达） |
| BOOT 键 | GPIO9 | **GPIO0**（S3 DevKitC-1） |
| 温度读数 | 正常 | 加了 `NAN` 防护（否则 stats JSON 非法） |
| 串口输出 | 原生 USB | **UART0 + CH343**（见下节），`ARDUINO_USB_CDC_ON_BOOT=0` |
| mDNS / 热点名 | c3adblock / C3-AdBlock-XXXX | **s3adblock / S3-AdBlock-XXXX** |
| C3 天线降功率特例 | 启用 | 仅 C3 编译时启用 |
| DNS 应答缓存 | 无（上游列为待办） | **有**，128 槽，重复查询约快 12 倍 |
| coredump 分区 | 无 | **64 KB**，崩溃可事后分析 |
| 首次启动日志 | 满屏 ERROR | 已清理（自动建状态文件 / NVS 预置） |

DNS 协议处理、客户端统计、配网门户、Web 面板、名单热更新、固件 OTA、安全措施
（Basic Auth + CSRF 头）全部沿用上游实现。

### 串口走 CH343，不是原生 USB

实测这块板子（N16R8）的串口是 **CH343 USB 转串口芯片**（`VID_1A86:PID_55D3`），
接在 S3 的 UART0（GPIO43 TX / GPIO44 RX）上，**没有引出原生 USB-JTAG**。

因此 `platformio.ini` 里刻意设为：

```ini
-DARDUINO_USB_MODE=1          ; 仍编译原生 USB-CDC 为 USBSerial，不碍事
-DARDUINO_USB_CDC_ON_BOOT=0   ; 让 Serial 指向 UART0 —— CH343 才看得到日志
```

若你换成真正接了原生 USB 的板子，把 `CDC_ON_BOOT` 改回 `1` 即可。
另外 flash 模式用了 **DIO**（不是 QIO）：CH343 板子同时用原生 USB 时 QIO 某些
模组会掉，DIO 更稳，实测启动正常。

## 硬件

- ESP32-S3 开发板，**至少 4 MB flash**；推荐 16 MB（N16R8 / N16R2 都可）。
- 无需 PSRAM，无需外接元件、屏幕或 LED。
- 供电要稳：用质量好的 USB 电源。廉价 USB 转接头在 WiFi 发射瞬间可能压降重启。
- 最好用 2.4 GHz WiFi。

## 一、电脑上要装的依赖

Windows 上只需两样：

1. **Python 3.10+**
2. **PlatformIO Core** + esptool 依赖

一键脚本（默认走清华 PyPI 镜像）：

```bat
setup-toolchain.bat
```

手动等价命令：

```bat
python -m pip install -U platformio -i https://pypi.tuna.tsinghua.edu.cn/simple
python -m pip install -t "%USERPROFILE%\.platformio\packages\tool-esptoolpy\_contrib" ^
  -i https://pypi.tuna.tsinghua.edu.cn/simple ^
  "cryptography~=45.0.3" "ecdsa~=0.19.1" "bitstring~=4.3.1" "reedsolo~=1.7.0" "intelhex~=2.3.0"
```

> 第二步很关键。PlatformIO 首次构建时会自己 `pip install` 这批包，在**国内
> 会长时间卡住（作者实测十几分钟无进展）。先手动装好，构建就顺畅了。
> 其余工具链（xtensa-esp32s3 编译器、Arduino core、esptool）由 PlatformIO 从
> `dl.registry.platformio.org` 自动下载，国内可直连，首次约 1.6 GB。

**不需要**安装 ESP-IDF、Arduino IDE 或任何驱动——S3 原生 USB 免驱；如果板子用的是
CH340/CP210x USB 转串口，Windows 会自动装驱动。

## 二、构建与烧录

```bat
copy src\secrets.example.h src\secrets.h
```

编辑 `src\secrets.h`：**务必改掉 `WEB_PASS` 和 `OTA_PASS`**。WiFi 可以留占位符，
首次开机用手机配网。

```bat
:: 1. 生成名单（国内源，约 9.7 万条）
python tools\build_cn_blocklist.py

:: 2. 编译 + 烧录固件
python -m platformio run -e s3_16mb -t upload

:: 3. 烧录名单文件系统
python -m platformio run -e s3_16mb -t uploadfs

:: 4. 看串口日志，记下 IP
python -m platformio device monitor
```

也可以一条命令搞定（自动补建名单、烧固件+文件系统、开串口）：

```bat
flash-16mb.bat            :: 自动找端口
flash-16mb.bat COM5       :: 指定端口
```

8 MB 用 `-e s3_8mb`，4 MB 用 `-e s3_4mb`。

烧录全程只需一次 USB。**之后固件和名单都能走 WiFi 更新**，不用再插线。

### 串口/端口

- 原生 USB 口：设备名形如 `USB 串行设备 (COM5)`，Windows 免驱。
- 如果 `pio` 找不到端口，指定：`--upload-port COM5`。
- S3 进入下载模式失败时：按住 **BOOT**，点一下 **RST**，再松开 BOOT。

## 三、首次配网与使用

1. 没配置 WiFi 时，板子开一个开放热点 **`S3-AdBlock-XXXX`**。
2. 手机连上它，通常会自动弹出配网页（或手动打开 `http://192.168.4.1`）。
3. 选/填你的 WiFi 名、输入密码 → 设备重启并连接。
4. 到路由器后台看它的 IP，或访问 **`http://s3adblock.local`**。

把要过滤的设备 DNS 指向板子 IP 即可。**只设一台设备测试最稳妥**；若要全屋生效，
在路由器 DHCP 里把 DNS 改成板子 IP，并把板子 IP 设成静态保留。

> 注意：路由器若同时下发 IPv6 DNS（RDNSS/DHCPv6），设备可能绕过板子直连 IPv6 DNS，
> 需要在路由器上关掉或改掉。

验证：

```bat
python tools\test_dns.py <板子IP>
```

预期：`doubleclick.net` → `0.0.0.0`（拦截），`github.com` → 真实 IP（放行）。

Windows 自带的等价命令：

```powershell
Resolve-DnsName doubleclick.net -Server <板子IP> -Type A -DnsOnly
Resolve-DnsName github.com       -Server <板子IP> -Type A -DnsOnly
```

## 四、Web 面板功能

`http://s3adblock.local`（或板子 IP）：

- **统计卡片**：拦截/放行总数、名单条数、客户端数、RSSI、温度、剩余 RAM、运行时长
- **暂停/恢复拦截**（30 秒 / 5 分钟 / 30 分钟 / 手动恢复）
- **客户端列表**：每个 IP 的拦截/放行计数，可 Ban/Unban 单个客户端
- **自定义拦截域名**：手动加/删
- **名单上传 / 远程定时更新**（填一个预生成 `blocklist.bin` 的 URL，按时拉取）
- **固件 OTA 上传**（传 `.pio\build\s3_16mb\firmware.bin`）
- **上游 DNS 设置**：手动 IP / 用路由器 DNS / 恢复默认
- **忘记 WiFi** → 重启回配网模式

所有会改状态的接口都要 HTTP Basic Auth + 自定义 CSRF 头（面板自带）。

## 五、名单

默认（`build_cn_blocklist.py`）：

- `https://anti-ad.net/adguard.txt`
- `https://anti-ad.net/easylist.txt`
- 通过 `ghproxy.net` 镜像拉 `hagezi pro`（加 `--aggressive`）

也可用国际列表：`python tools\build_cn_blocklist.py --global`
（StevenBlack + Hagezi Light，经 ghproxy 镜像）。

自定义源：

```bat
python tools\build_cn_blocklist.py --out data\blocklist.bin https://某地址/list.txt
```

支持格式：hosts 文件、纯域名列表、AdGuard/AdBlock 基础规则（`||d^`、`@@||d^`）。
DNS 哈希表无法表达的规则（正则、通配、`$` 修饰、外观规则）会被跳过并计数。

`tools\verify_index.py` 会**在电脑上按固件的查找逻辑**逐条验证名单，确保零漏判：

```bat
python tools\verify_index.py data\blocklist.bin 8192 256
```

## 六、容量与分区

| 配置 | app0 / app1 | LittleFS | 名单上限（5 B/条） | 索引 |
|---|---|---|---|---|
| `s3_16mb` | 3 MB × 2 | 9.9 MB | ~200 万条（受索引限制） | 8192×256 |
| `s3_8mb` | 1.5 MB × 2 | 5 MB | ~100 万条 | 8192×256 |
| `s3_4mb` | 1.5 MB × 1（无固件 OTA） | 2.4 MB | ~48 万条 | 4096×256 |

固件实际约 1.03 MB、静态 RAM 约 169 KB（含 128 槽 DNS 缓存，共 64 KB）；
不启用缓存时约 103 KB。

**索引上限很重要**：`inFlash()` 每个桶最多扫描 `MAX_RANGE` 条，桶太宽会**静默漏判**。
`INDEX_ENTRIES × MAX_RANGE` 就是绝对上限。16 MB 默认 8192×256 = 200 万条，
已用 200 万条合成数据实测（最宽桶 246 ≤ 256，零漏判）。要装更大的名单，就调高
`platformio.ini` 里的 `INDEX_ENTRIES`/`MAX_RANGE`（会多占 RAM：8192 条索引 = 40 KB）。

## 六点五、实机实测数据

以下全部是在这块 N16R8 板子上、通过真实 WiFi 网络测出来的，不是估算。

| 指标 | 实测值 |
|---|---|
| 芯片 | ESP32-S3 rev v0.2，16 MB flash（GigaDevice quad），8 MB PSRAM |
| 固件 / 静态 RAM | 1.03 MB / 169 KB（32.7% / 52.7%） |
| 空闲堆 | 约 202 KB |
| 名单 | 96,961 条，零哈希碰撞，零漏判 |
| 启动耗时 | 约 1 秒（含文件系统与索引加载） |
| 拦截查询（命中名单） | **4–7 ms** 中位数 |
| 允许查询（缓存命中） | **3–7 ms** 中位数 |
| 允许查询（走上游） | 25–230 ms（取决于上游与 WiFi 抖动） |
| 真实混合负载（200 次） | 中位数 7.3 ms，p95 145 ms，**缓存命中率 98%** |
| 压力测试（430 次真实查询） | **99.8% 成功**，内存零泄漏（±220 B 波动） |
| 空闲温度 / RSSI | 约 47 °C / −60 dBm |

**关于延迟抖动**：即使关闭 WiFi 省电（`setSleep(false)`），仍可能出现
100 ms+ 的尖峰，约每 10 次一次。这是 2.4 GHz 链路层的重传/信道竞争，不是固件
问题（排查过 lwIP 队列与 WiFi 缓冲，配置充足）。**DNS 缓存把这类抖动挡在被
拦截的那一侧**：重复查询直接本地回包，根本不碰 WiFi 往返。

### DNS 应答缓存说明

- 128 槽直接映射表，按 `(question, qtype)` 做键，保留 TTL 内生效。
- 命中直接回包，未命中才转发上游；命中率统计在 `/stats.json` 的
  `chits`/`cmiss` 字段。
- 存缓存时**剥离 OPT/EDNS 伪记录**并修正 `ARCOUNT`：它描述的是上游那一跳，
  不能回传给没发 EDNS 的客户端。
- 名单更新、自定义规则增删、上游 DNS 变更、暂停恢复时自动清空缓存，
  避免返回过期或被规则改判的结果。
- NXDOMAIN / 空应答不缓存（上游若临时抖动，缓存住会导致长时间解析失败）。

## 七、代码结构

```
platformio.ini              三套 S3 配置 + C3 参考配置
partitions_s3_16mb.csv      app 3 MB×2 + LittleFS 9.9 MB + coredump 64 KB
partitions_s3_8mb.csv       1.5 MB OTA×2 + 5 MB LittleFS
partitions_s3_4mb.csv       单 app + 2.4 MB LittleFS
src/main.cpp                DNS 服务 / 应答缓存 / 配网 / Web API / OTA
src/page.h                  面板 HTML（PROGMEM）
src/secrets.h               你的 WiFi/密码（gitignore）
tools/build_blocklist.py    上游原版：任何名单 → 排序哈希 blob
tools/build_cn_blocklist.py 国内源封装 + 自动校验
tools/verify_index.py       在 PC 上复现固件索引查找，校验零漏判
tools/test_dns.py           向板子发 DNS 查询做冒烟测试
setup-toolchain.bat         Windows 一键装依赖
flash-16mb.bat              一键烧录（固件 + 文件系统）
```

## 八、常见问题

**编译时卡在 `pip install ... cryptography`**
见上文「一、电脑上要装的依赖」——先在修饰镜像手动装好 esptool 的 `_contrib`。

**下载平台包失败**
本配置用的是官方 registry（`espressif32@6.12.0`），不是 GitHub 直链，国内可下。
若你的网络连 `dl.registry.platformio.org` 都困难，才需要配代理。

**刷完串口没输出 / 一直重启**
- 确认烧的是 S3 的固件，不是 C3 的。
- 供电不足会 brownout：换质量好的 USB 电源再试。
- 原生 USB 口在刚启动时可能吞掉前几行日志，复位一次即可。

**能连 WiFi 但解析超时**
上游 DNS 可能被墙。进面板 **UPSTREAM DNS** 改成 `223.5.5.5` 或路由器 DNS。

**某些广告还在**
1. 这些广告和正常内容共用一个域名（DNS 层拦不住）。
2. 浏览器开了加密 DNS（DoH/DoT）或走了代理/VPN，绕过了板子。
3. 设备用了 IPv6 DNS。
4. 名单里没有该域名：加自定义规则，或换更大的名单。

**内存告警**
S3 只有 320 KB 内部 SRAM。若调大了 `INDEX_ENTRIES` 又出现不稳定，串口看
`[mem] free heap` 是否长期偏低。

## 九、安全边界

- 面板 HTTP 明文，Basic Auth 只是**局域网信任边界**，不是加密。
- 建议不要把板子的 80 端口映射到公网。
- 配网热点是开放的（设计如此，否则没法首次加入）。
- `secrets.h` 已在 gitignore，别提交真实密码。

## 十、许可证

MIT，见 `LICENSE`。

本项目是 [M-Abozaid/esp32-c3-adblock](https://github.com/M-Abozaid/esp32-c3-adblock)
的 ESP32-S3 移植版，保留其 MIT 许可证与版权声明。上游实现受
[s60sc/ESP32_AdBlocker](https://github.com/s60sc/ESP32_AdBlocker) 启发。

在原版基础上的改动（S3 适配、CH343 串口、DIO flash 模式、DNS 应答缓存、
索引扩容、日志清理等）以同样的 MIT 条款发布。
