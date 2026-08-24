---
AIGC:
    Label: "1"
    ContentProducer: 001191440300708461136T1XGW3
    ProduceID: d4d6906990f8f3ccc3ff042cb0007e6b_1e303b359f8711f1a413525400287e28
    ReservedCode1: qVXIr/vVoDBrSWszeJh1J97OVN09p3JyV2BalqCyxqCyStxNOzgi9r7f/rZuXhqbxB0YdkgC4wMjSiq3FFYhNH0gazpPjXm3Hd1YfnBH+vT+ulX/8uZgWpDiqdwP9+/c9kyGX7hj9OvaZ338T0ZMV4QAoWRaWBlKBCjS8LfWndO2f5aNIqjewlOs7kk=
    ContentPropagator: 001191440300708461136T1XGW3
    PropagateID: d4d6906990f8f3ccc3ff042cb0007e6b_1e303b359f8711f1a413525400287e28
    ReservedCode2: qVXIr/vVoDBrSWszeJh1J97OVN09p3JyV2BalqCyxqCyStxNOzgi9r7f/rZuXhqbxB0YdkgC4wMjSiq3FFYhNH0gazpPjXm3Hd1YfnBH+vT+ulX/8uZgWpDiqdwP9+/c9kyGX7hj9OvaZ338T0ZMV4QAoWRaWBlKBCjS8LfWndO2f5aNIqjewlOs7kk=
---

# VHDX 父盘只读保护工具（VhdxLock）开发文档

版本：v1.7（归档版）
归档日期：2026-08-24

---

## 1. 项目概述

**用途**：防止误挂载/误打开 VHDX/VHD 父盘导致差分磁盘（子盘）失效。

**背景**：用户在 Hyper-V 中使用差分磁盘（父盘 + 子盘），曾误挂载打开父盘导致子盘（Hyper-V 系统盘子盘）失效。核心诉求是给父盘加只读保护，且**换电脑复制后仍然生效**。

**技术路线**：VHDX 格式本身无内置只读标志位，Windows 生态保护父盘的标准做法是设置 NTFS 文件只读属性（`attrib +R`，跨电脑普通复制保留）+ ACL 硬锁（拒绝 Everyone 写入，防程序绕过只读属性强制写入）。

**交付形态**：绿色单文件 exe（.NET Framework 4.8 编译，无需安装、无外部依赖），GUI + CLI 双模式。

---

## 2. 功能特性

| 功能 | 说明 |
|---|---|
| 拖拽识别 | 拖入 VHDX/VHD 自动识别父盘/子盘、只读状态、ACL 状态、文件系统 |
| 一键保护 | 设置只读属性 + ACL 硬锁（自动按正确顺序：先只读后 ACL） |
| 一键解锁 | 解除 ACL + 只读属性（自动按正确顺序：先 ACL 后只读） |
| 设置只读 | 仅设只读属性，不碰 ACL（v1.5） |
| 打开父盘 | 子盘场景一键打开父盘所在目录并选中（v1.5） |
| 生成哈希 | SHA256 后台分块计算 + 进度条 + 可取消（v1.3/v1.6 修复） |
| 校验哈希 | 对比 .sha256 记录文件校验文件是否被修改 |
| CLI 模式 | lock / unlock / acl / acloff / hash / verify 子命令 |
| 拖文件到 exe | 直接拖文件到 exe 图标自动启动 GUI 并加载（v1.2） |
| 防呆设计 | 按钮禁用强灰度；加解锁顺序自动处理（v1.3） |
| 计算中防拖拽 | 哈希生成/校验过程中禁止拖入新盘（v1.6） |
| ACL 兼容解锁 | 解锁移除所有"Deny Everyone 且含 Write 位"规则，兼容外部工具（v1.7） |

---

## 3. 版本历史

| 版本 | 变更 |
|---|---|
| v1.1 | 新增 ACL 硬锁（拒绝 Everyone 写入）+ SHA256 哈希生成/校验 |
| v1.2 | 支持拖文件到 exe 图标自动启动 GUI 并加载（Main default 分支 new MainForm(args[0])，Shown 事件 HandleFile） |
| v1.3 | 一键保护/一键解锁防呆（自动顺序）；哈希后台计算 + 进度 + 取消；禁用按钮强灰度（DisabledBack=Color.FromArgb(228,231,235)、DisabledFore=Color.FromArgb(165,170,178)） |
| v1.4 | 重构精简按钮：移除"设为只读/解锁保护/ACL 硬锁/解锁 ACL"四个重复按钮，仅保留 保护/解锁/生成哈希/校验哈希 |
| v1.5 | 新增"设置只读"按钮（仅 SetReadOnly 不碰 ACL）；新增"打开父盘"按钮（仅子盘时显示，调用 explorer.exe /select,"父盘路径"） |
| v1.6 | 修复取消计算按钮不可点（StartHash 补 Enabled=true）；哈希过程中 HandleFile 拦截拖入新盘 |
| v1.7 | ACL 解锁兼容外部工具规则：遍历移除所有"Deny Everyone 且含 Write 位"的规则（含 FullControl） |

---

## 4. 使用说明

### GUI 模式
- 双击运行，拖拽 VHDX/VHD 文件到窗口
- 父盘：显示"设为只读/解锁"按钮（只读态显示"解锁"，读写态显示"设为只读"）
- 子盘：禁止设置保护，显示"打开父盘"按钮
- 哈希计算中：可点"取消计算"，禁止拖入新盘

### CLI 模式
```
VhdxLock.exe <文件>            分析（显示格式/类型/只读/ACL/文件系统）
VhdxLock.exe lock <文件>       只读 + ACL 硬锁
VhdxLock.exe unlock <文件>     解锁只读 + ACL
VhdxLock.exe acl <文件>        仅 ACL 硬锁
VhdxLock.exe acloff <文件>     仅解 ACL
VhdxLock.exe hash <文件>       生成 SHA256 哈希记录（同名 .sha256）
VhdxLock.exe verify <文件>     校验 SHA256 哈希
```

---

## 5. 架构与实现说明

### 5.1 代码结构（单文件 VhdxLock.cs，约 990 行）

| 区域 | 说明 |
|---|---|
| Main 入口 | CLI 子命令分发；default 分支启动 GUI（拖拽场景 new MainForm(args[0])） |
| MainForm | WinForms 界面：拖拽区、状态显示、按钮（保护/解锁/设置只读/生成哈希/校验哈希/打开父盘） |
| Analyze / ParseVhdx / ParseVhd | 文件格式解析，识别父盘/子盘、只读、ACL、文件系统 |
| HasAclLock | 检测"Deny Everyone 且含 Write 位"规则 |
| SetAclLock | 加锁/解锁 ACL（v1.7 增强解锁兼容性） |
| SetReadOnly | 设置/清除 NTFS 只读属性 |
| HashFile / GenHashRecord / VerifyHash | SHA256 分块计算、记录文件读写、校验 |
| BackgroundWorker | 哈希后台计算 + 进度上报 + 取消 |

### 5.2 VHDX 格式解析要点（MS-VHDX）

```
文件标识符(64KiB, 签名"vhdxfile")
  → 2个 Image Header(4KiB, "head" @0x10000/0x20000，选 SequenceNumber 大的)
  → 2个 Region Table(64KiB, "regi" @0x30000)
  → Metadata Region("metadata" @0x200000)
```

- Metadata Table Header 32 字节，EntryCount 位于偏移 **10**（2 字节）
- 表项从偏移 32 起，每项 32 字节：GUID(16) + ItemOffset(4) + ItemLength(4) + IsUser(4) + Reserved(4)
- **File Parameters** GUID=`caa16737-fa36-4d43-b3b6-33f0aa44e76b`，数据 8 字节：BlockSize(4) + Flags(4)，Flags bit1=HasParent 差分标志
- **Parent Locator** ItemId=`a8d35f2d-b30b-454d-abf7-d3d84834ab0c`（类型 GUID=`b04aefb7-d19e-4a81-b789-25b8e9445913`），Header 20 字节、Entry 12 字节、key/value UTF-16LE，键 `absolute_win32_path` 存父盘路径
- **VHD(v1)** footer 512 字节大端：签名"conectix"@0；DiskType@60 大端，2=Fixed 3=Dynamic **4=Differencing**（差分判断 diskType==4）

### 5.3 ACL 加解锁顺序（关键陷阱）

- **加锁**：先设只读 → 再加 ACL（无顺序问题）
- **解锁**：必须先解 ACL → 再解只读。因为 ACL 的 Deny Everyone Write 会拦截文件属性修改（WRITE_ATTRIBUTES 属于 Write 组合位），未先解除 ACL 无法改只读属性
- **ACL 硬锁实现**：FileSystemAccessRule(Everyone SID=S-1-1-0, FileSystemRights.Write, Deny)；Hyper-V 读父盘不受影响
- **ACL 传输限制**：普通复制丢 ACL，需 robocopy /COPYALL 或 NTFS U 盘保留；exFAT/FAT32 不存 ACL

### 5.4 哈希计算

- SHA256 分块（4MB/块）TransformBlock + ProgressChanged 百分比 + 取消按钮，避免 UI 阻塞
- 记录文件：`<文件名>.sha256`（含哈希值 + 记录时间）
- v1.6 修复：取消按钮 Enabled=true 才可点；计算中 HandleFile 拦截拖入新盘

---

## 6. 踩坑记录与经验教训

1. **误以为 VHDX 有文件头只读位**：查证 MS-VHDX 规范（2.2.2 Headers 与 2.6.2 Known Metadata Items）确认无只读字段，改用 NTFS 只读属性 + ACL 实现跨电脑保护。教训：实现前务必先验证格式假设。
2. **初版三错**：
   - Metadata EntryCount 偏移 6 → 正确为 10
   - Parent Locator ItemId 误认及 48 字节结构 → 正确为 `a8d35f2d...` 及 12 字节 Entry
   - VHD DiskType 小端且 ==2 → 正确为大端且 ==4（Differencing）
3. **解锁顺序颠倒失败**：先清只读再解 ACL 报"访问被拒绝"，必须"先解 ACL 再解只读"。
4. **取消计算没反应**：btnCancelHash 仅 Visible=true 未 Enabled=true，按钮灰色不可点。
5. **哈希中可拖入新盘**：HandleFile 未检查 hashRunning，后台计算时文件被替换。修复：入口拦截 + 提示。
6. **ACL 外部工具兼容**：RemoveAccessRuleSpecific 精确匹配，Deny Everyone FullControl 移除不掉 → v1.7 改为遍历移除所有"Deny Everyone 且含 Write 位"规则。
7. **winexe 测试挂起**：CLI 直接传文件路径走 default 分支启动 GUI 导致 shell 挂起超时；须用显式子命令（lock/unlock/hash/verify）测试；GUI 实测用 Start-Process 启动后 Sleep 再 Stop-Process 验证存活。

---

## 7. 编译方法

依赖：Windows + .NET Framework 4.8（系统自带 csc.exe，无需 VS）

```powershell
$csc = "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe"

# GUI 版（winexe）
& $csc /nologo /target:winexe /out:VhdxLock.exe `
  /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.dll VhdxLock.cs

# CLI 测试版（console，输出到控制台）
& $csc /nologo /target:exe /out:VhdxLock_cli.exe `
  /r:System.Windows.Forms.dll /r:System.Drawing.dll /r:System.dll VhdxLock.cs
```

**必须引用**：`System.Windows.Forms.dll`、`System.Drawing.dll`、`System.dll`；代码已 using `System.ComponentModel`（BackgroundWorker）、`System.Diagnostics`（Process 打开资源管理器）、`System.Collections.Generic`（List）。

---

## 8. 测试方法

### 测试文件
- 合法 VHDX 载体：`vhdx_test\regress_min.vhdx`（Python 手工构造的最小合法 VHDX：vhdxfile 签名 + head + regi Region Table + metadata File Parameters，Flags=0 非差分）
- 历史测试：`vhdx_test\parent.vhdx`（64MB Fixed）+ `child.vhdx`（Differencing）+ `parent.vhdx.sha256`

### CLI 回归
```powershell
VhdxLock_cli.exe lock   <file>   # 应显示"已启用只读，已启用 ACL 硬锁"
VhdxLock_cli.exe hash   <file>   # 生成 .sha256
VhdxLock_cli.exe verify <file>   # 应显示"一致"
VhdxLock_cli.exe unlock <file>   # 应显示"已解除只读，已解除 ACL 硬锁"
```

### 外部 ACL 兼容测试
```powershell
# 构造外部规则后跑 acloff/unlock 验证
Set-DenyRule <file> S-1-1-0 Write        # Deny Everyone Write → 应解锁成功
Set-DenyRule <file> S-1-1-0 FullControl  # Deny Everyone FullControl → 管理员下应解锁成功
Set-DenyRule <file> <当前用户SID> Write  # Deny 特定用户 → 应保留不动
```

### GUI 冒烟
```powershell
Start-Process VhdxLock.exe
Start-Sleep 3
Get-Process VhdxLock  # 确认存活，MainWindowTitle 应为 "VHDX 父盘只读保护 v1.7"
Stop-Process -Name VhdxLock
```

---

## 9. 待办/未决事项

- [ ] 是否加"只读单独设置"的 CLI 命令方便脚本调用（v1.5 时询问，用户未回复）
- [ ] 是否复制 exe 到桌面（历史遗留询问，未决）
- [ ] GUI 截图验证时需注意窗口遮挡（IDE 可能抢占前台）

---

## 10. 归档内容

| 文件 | 说明 |
|---|---|
| VhdxLock.cs | 完整源码（v1.7，单文件） |
| README.md | 本开发文档（含版本历史、架构、踩坑、编译/测试方法） |
| VhdxLock.exe | 已编译成品（v1.7，绿色单文件） |
*（内容由AI生成，仅供参考）*
