// VHDX 父盘只读保护工具 v1.7
// v1.7 增强：ACL 解锁兼容外部工具设置的规则（Deny Everyone 且含 Write 位的所有规则，含 FullControl）。
// v1.6 修复：取消计算按钮可点击生效；哈希生成/校验过程中禁止拖入新盘（HandleFile 拦截）。
// v1.5 新增："设置只读"仅设只读属性不动 ACL；"打开父盘"仅子盘时显示，一键打开父盘所在目录。
// 绿色单文件，无需安装。拖拽 VHDX 到窗口即可识别父盘/子盘及只读状态。
// v1.1 新增：ACL 硬锁（拒绝 Everyone 写入）+ SHA256 哈希生成/校验
// v1.3 新增：一键保护/一键解锁防呆、哈希后台计算+进度+取消、禁用按钮强灰度
// v1.4 重构：精简按钮。保护=只读+ACL 一体；解锁=ACL+只读 一体；移除重复的
//   "设为只读/解锁保护/ACL 硬锁/解锁 ACL" 四个按钮，仅保留 保护/解锁/生成哈希/校验哈希。
// 用法：GUI 拖拽；或命令行：
//   VhdxLock.exe <文件>            分析
//   VhdxLock.exe lock <文件>       只读 + ACL 硬锁
//   VhdxLock.exe unlock <文件>     解锁只读 + ACL
//   VhdxLock.exe hash <文件>       生成 SHA256 哈希记录
//   VhdxLock.exe verify <文件>     校验 SHA256 哈希

using System;
using System.IO;
using System.Text;
using System.Drawing;
using System.Windows.Forms;
using System.Diagnostics;
using System.ComponentModel;
using System.Collections.Generic;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Security.Cryptography;

public class VhdxLockApp
{
    static readonly Guid GuidMetadataRegion  = new Guid("8b7ca206-4790-4b9a-b8fe-575f050f886e");
    static readonly Guid GuidFileParameters  = new Guid("caa16737-fa36-4d43-b3b6-33f0aa44e76b");
    static readonly Guid GuidParentLocator   = new Guid("b04aefb7-d19e-4a81-b789-25b8e9445913");
    static readonly Guid GuidParentLocator2  = new Guid("a8d35f2d-b30b-454d-abf7-d3d84834ab0c");
    static readonly SecurityIdentifier SidEveryone = new SecurityIdentifier("S-1-1-0");

    public class Analysis
    {
        public bool   Ok;
        public string Error;
        public string FilePath;
        public bool   IsChild;       // 差分盘（子盘）
        public bool   IsReadOnly;    // 文件只读属性
        public bool   HasAclLock;    // ACL 拒绝写入硬锁
        public string ParentPath;    // 子盘时的父盘路径
        public string VolumeFs;      // 所在卷文件系统
        public string Format;        // VHDX / VHD
        public long   FileSize;
    }

    [STAThread]
    static int Main(string[] args)
    {
        if (args.Length > 0)
        {
            string cmd = args[0].ToLowerInvariant();
            string file = args.Length > 1 ? args[1] : null;
            switch (cmd)
            {
                case "lock":
                    if (file == null) { Console.WriteLine("用法: VhdxLock.exe lock <文件>"); return 2; }
                    return RunCli(file, true, true);
                case "unlock":
                    if (file == null) { Console.WriteLine("用法: VhdxLock.exe unlock <文件>"); return 2; }
                    return RunCli(file, false, false);
                case "acl":
                    if (file == null) { Console.WriteLine("用法: VhdxLock.exe acl <文件>"); return 2; }
                    return RunAclCli(file, true);
                case "acloff":
                    if (file == null) { Console.WriteLine("用法: VhdxLock.exe acloff <文件>"); return 2; }
                    return RunAclCli(file, false);
                case "hash":
                    if (file == null) { Console.WriteLine("用法: VhdxLock.exe hash <文件>"); return 2; }
                    return RunHashCli(file);
                case "verify":
                    if (file == null) { Console.WriteLine("用法: VhdxLock.exe verify <文件>"); return 2; }
                    return RunVerifyCli(file);
                default:
                    // 拖拽文件到工具图标（Windows 会把路径作为参数传入）：启动 GUI 并自动加载
                    Application.EnableVisualStyles();
                    Application.SetCompatibleTextRenderingDefault(false);
                    Application.Run(new MainForm(args[0]));
                    return 0;
            }
        }
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);
        Application.Run(new MainForm());
        return 0;
    }

    // ---- CLI 辅助 ----
    static int RunCli(string file, bool ro, bool acl)
    {
        Analysis a = Analyze(file);
        if (!a.Ok) { Console.WriteLine("ERROR: " + a.Error); return 2; }
        if (a.IsChild)
        {
            Console.WriteLine("ERROR: 这是子盘（差分磁盘），禁止设置保护！");
            if (!string.IsNullOrEmpty(a.ParentPath)) Console.WriteLine("父盘: " + a.ParentPath);
            return 2;
        }
        // 加锁：先只读后 ACL；解锁：必须先解 ACL（deny 会挡属性修改）再解只读
        string err1, err2;
        if (ro)
        {
            err1 = SetReadOnly(file, ro);
            if (err1 != null) { Console.WriteLine("ERROR: 设置只读失败: " + err1); return 2; }
            err2 = SetAclLock(file, acl);
            if (err2 != null) { Console.WriteLine("ERROR: 设置 ACL 失败: " + err2); return 2; }
        }
        else
        {
            err2 = SetAclLock(file, acl);
            if (err2 != null) { Console.WriteLine("ERROR: 设置 ACL 失败: " + err2); return 2; }
            err1 = SetReadOnly(file, ro);
            if (err1 != null) { Console.WriteLine("ERROR: 设置只读失败: " + err1); return 2; }
        }
        Console.WriteLine(DumpText(Analyze(file)));
        Console.WriteLine("已" + (ro ? "启用只读" : "解除只读") + "，已" + (acl ? "启用 ACL 硬锁" : "解除 ACL 硬锁"));
        return 0;
    }

    static int RunAclCli(string file, bool on)
    {
        if (!File.Exists(file)) { Console.WriteLine("ERROR: 文件不存在: " + file); return 2; }
        string err = SetAclLock(file, on);
        if (err != null) { Console.WriteLine("ERROR: " + err); return 2; }
        Console.WriteLine("ACL 硬锁已" + (on ? "启用（拒绝 Everyone 写入）" : "解除"));
        return 0;
    }

    static int RunHashCli(string file)
    {
        if (!File.Exists(file)) { Console.WriteLine("ERROR: 文件不存在: " + file); return 2; }
        string rec = GenHashRecord(file);
        Console.WriteLine("哈希记录已生成: " + rec);
        return 0;
    }

    static int RunVerifyCli(string file)
    {
        if (!File.Exists(file)) { Console.WriteLine("ERROR: 文件不存在: " + file); return 2; }
        Console.WriteLine(VerifyHash(file));
        return 0;
    }

    static string DumpText(Analysis a)
    {
        if (!a.Ok) return "ERROR: " + a.Error;
        StringBuilder sb = new StringBuilder();
        sb.AppendLine("文件: " + a.FilePath);
        sb.AppendLine("格式: " + a.Format);
        sb.AppendLine("类型: " + (a.IsChild ? "子盘（差分磁盘）" : "父盘"));
        sb.AppendLine("只读属性: " + (a.IsReadOnly ? "只读" : "读写"));
        sb.AppendLine("ACL 硬锁: " + (a.HasAclLock ? "已启用（拒绝 Everyone 写入）" : "未启用"));
        sb.AppendLine("卷文件系统: " + a.VolumeFs);
        if (a.IsChild && !string.IsNullOrEmpty(a.ParentPath))
            sb.AppendLine("父盘: " + a.ParentPath);
        return sb.ToString();
    }

    public static Analysis Analyze(string path)
    {
        Analysis a = new Analysis();
        a.FilePath = path;
        try
        {
            if (string.IsNullOrEmpty(path) || !File.Exists(path))
            {
                a.Error = "文件不存在或无法访问。"; return a;
            }
            string ext = Path.GetExtension(path).ToLowerInvariant();
            a.FileSize = new FileInfo(path).Length;

            if (ext == ".vhd")
            {
                a.Format = "VHD";
                if (!ParseVhd(path, a)) return a;
            }
            else if (ext == ".vhdx")
            {
                a.Format = "VHDX";
                if (!ParseVhdx(path, a)) return a;
            }
            else
            {
                a.Error = "仅支持 .vhdx / .vhd 虚拟磁盘文件。"; return a;
            }

            try
            {
                a.IsReadOnly = (File.GetAttributes(path) & FileAttributes.ReadOnly) != 0;
            }
            catch { a.IsReadOnly = false; }

            try
            {
                a.HasAclLock = HasAclLock(path);
            }
            catch { a.HasAclLock = false; }

            try
            {
                string root = Path.GetPathRoot(Path.GetFullPath(path));
                DriveInfo di = new DriveInfo(root);
                a.VolumeFs = di.IsReady ? di.DriveFormat : "未知";
            }
            catch { a.VolumeFs = "未知"; }

            a.Ok = true;
            return a;
        }
        catch (Exception ex)
        {
            a.Error = "解析失败: " + ex.Message;
            return a;
        }
    }

    // ---- VHD 老格式：读文件末尾 512 字节 footer，DiskType==4 为差分盘 ----
    static bool ParseVhd(string path, Analysis a)
    {
        using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            long size = fs.Length;
            if (size < 512) { a.Error = "VHD 文件过小，无法解析。"; return false; }
            byte[] footer = new byte[512];
            fs.Position = size - 512;
            fs.Read(footer, 0, 512);
            string sig = Encoding.ASCII.GetString(footer, 0, 8);
            if (sig != "conectix") { a.Error = "VHD 文件签名无效（非有效 VHD）。"; return false; }
            uint diskType = (uint)((footer[60] << 24) | (footer[61] << 16) | (footer[62] << 8) | footer[63]);
            a.IsChild = (diskType == 4);
            return true;
        }
    }

    // ---- VHDX：解析文件头、Region Table、Metadata Region ----
    static bool ParseVhdx(string path, Analysis a)
    {
        using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            byte[] sig0 = new byte[8];
            fs.Position = 0;
            fs.Read(sig0, 0, 8);
            if (Encoding.ASCII.GetString(sig0) != "vhdxfile")
            {
                a.Error = "VHDX 文件签名无效（非有效 VHDX）。";
                return false;
            }

            long headerOff = PickCurrentHeader(fs);

            byte[] region = new byte[65536];
            fs.Position = 0x30000;
            int rd = fs.Read(region, 0, region.Length);
            if (rd < 64 || Encoding.ASCII.GetString(region, 0, 4) != "regi")
            {
                a.Error = "Region Table 读取失败。";
                return false;
            }
            uint entryCount = BitConverter.ToUInt32(region, 8);

            long metaOff = -1;
            for (int i = 0; i < entryCount; i++)
            {
                int p = 16 + i * 32;
                if (p + 32 > region.Length) break;
                byte[] g = new byte[16];
                Array.Copy(region, p, g, 0, 16);
                Guid gid = new Guid(g);
                if (gid == GuidMetadataRegion)
                {
                    metaOff = (long)BitConverter.ToUInt64(region, p + 16);
                    break;
                }
            }
            if (metaOff < 0)
            {
                a.Error = "未找到 Metadata Region（文件可能损坏）。";
                return false;
            }

            byte[] metaHead = new byte[64];
            fs.Position = metaOff;
            fs.Read(metaHead, 0, 64);
            if (Encoding.ASCII.GetString(metaHead, 0, 8) != "metadata")
            {
                a.Error = "Metadata 表头签名无效。";
                return false;
            }
            uint metaCount = BitConverter.ToUInt16(metaHead, 10);
            if (metaCount > 1024) metaCount = 1024;

            bool foundParams = false;
            for (int i = 0; i < metaCount; i++)
            {
                int p = 32 + i * 32;
                if (p + 32 > 64 + 32 * 1024) break;
                byte[] entry = new byte[32];
                fs.Position = metaOff + p;
                int er = fs.Read(entry, 0, 32);
                if (er < 32) break;
                byte[] gg = new byte[16];
                Array.Copy(entry, 0, gg, 0, 16);
                Guid gid = new Guid(gg);
                uint itemOff = BitConverter.ToUInt32(entry, 16);
                uint itemLen = BitConverter.ToUInt32(entry, 20);
                if (gid == GuidFileParameters)
                {
                    byte[] fp = new byte[8];
                    fs.Position = metaOff + itemOff;
                    fs.Read(fp, 0, 8);
                    uint flags = BitConverter.ToUInt32(fp, 4);
                    a.IsChild = (flags & 0x02) != 0;
                    foundParams = true;
                }
                else if (gid == GuidParentLocator || gid == GuidParentLocator2)
                {
                    a.ParentPath = ParseParentLocator(fs, metaOff + itemOff, itemLen);
                }
            }

            if (!foundParams)
            {
                a.Error = "未找到 File Parameters 元数据项（文件可能损坏）。";
                return false;
            }
            return true;
        }
    }

    static long PickCurrentHeader(FileStream fs)
    {
        long best = 0x10000;
        ulong bestSeq = 0;
        foreach (long off in new long[] { 0x10000, 0x20000 })
        {
            byte[] h = new byte[8];
            fs.Position = off;
            fs.Read(h, 0, 8);
            if (Encoding.ASCII.GetString(h, 0, 4) != "head") continue;
            byte[] seq = new byte[8];
            fs.Position = off + 8;
            fs.Read(seq, 0, 8);
            ulong s = BitConverter.ToUInt64(seq, 0);
            if (s >= bestSeq) { bestSeq = s; best = off; }
        }
        return best;
    }

    static string ParseParentLocator(FileStream fs, long itemStart, uint itemLen)
    {
        try
        {
            byte[] head = new byte[20];
            fs.Position = itemStart;
            fs.Read(head, 0, 20);
            uint kvCount = BitConverter.ToUInt16(head, 18);
            if (kvCount > 64) kvCount = 64;

            string absolutePath = null;
            string anyValue = null;
            for (int i = 0; i < kvCount; i++)
            {
                byte[] e = new byte[12];
                fs.Position = itemStart + 20 + i * 12;
                int r = fs.Read(e, 0, 12);
                if (r < 12) break;
                uint keyOff = BitConverter.ToUInt32(e, 0);
                uint valOff = BitConverter.ToUInt32(e, 4);
                uint keyLen = BitConverter.ToUInt16(e, 8);
                uint valLen = BitConverter.ToUInt16(e, 10);
                if (keyOff + keyLen > itemLen || valOff + valLen > itemLen) continue;
                if (keyLen > 256 || valLen > 4096) continue;

                byte[] kb = new byte[keyLen];
                fs.Position = itemStart + keyOff;
                fs.Read(kb, 0, (int)keyLen);
                string key = Encoding.Unicode.GetString(kb);

                byte[] vb = new byte[valLen];
                fs.Position = itemStart + valOff;
                fs.Read(vb, 0, (int)valLen);
                string val = Encoding.Unicode.GetString(vb);

                if (string.IsNullOrEmpty(anyValue) && !string.IsNullOrEmpty(val))
                    anyValue = val;
                if (key == "absolute_win32_path" && !string.IsNullOrEmpty(val))
                    absolutePath = val;
            }
            if (!string.IsNullOrEmpty(absolutePath)) return CleanPath(absolutePath);
            if (!string.IsNullOrEmpty(anyValue)) return CleanPath(anyValue);
        }
        catch { }
        return null;
    }

    static string CleanPath(string s)
    {
        s = s.Trim();
        if (s.StartsWith("\\??\\")) s = s.Substring(4);
        if (s.StartsWith("\\\\?\\")) s = s.Substring(4);
        return s;
    }

    // ---- 设置/解锁只读 ----
    public static string SetReadOnly(string path, bool ro)
    {
        try
        {
            FileAttributes fa = File.GetAttributes(path);
            if (ro) fa |= FileAttributes.ReadOnly;
            else    fa &= ~FileAttributes.ReadOnly;
            File.SetAttributes(path, fa);
            return null;
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    // ---- ACL 硬锁：拒绝 Everyone 写入 ----
    public static bool HasAclLock(string path)
    {
        FileSecurity fs = File.GetAccessControl(path);
        foreach (FileSystemAccessRule r in fs.GetAccessRules(true, true, typeof(SecurityIdentifier)))
        {
            if (r.AccessControlType == AccessControlType.Deny &&
                (r.FileSystemRights & FileSystemRights.Write) != 0 &&
                r.IdentityReference.Value == SidEveryone.Value)
                return true;
        }
        return false;
    }

    public static string SetAclLock(string path, bool on)
    {
        try
        {
            FileSecurity fs = File.GetAccessControl(path);
            // 解锁：移除所有“拒绝 Everyone 且含 Write 位”的规则（兼容 Deny Write / Deny FullControl 等外部工具设置的 ACL）
            FileSystemAccessRule denyWrite = new FileSystemAccessRule(
                SidEveryone, FileSystemRights.Write, AccessControlType.Deny);
            if (!on)
            {
                List<FileSystemAccessRule> toRemove = new List<FileSystemAccessRule>();
                foreach (FileSystemAccessRule r in fs.GetAccessRules(true, true, typeof(SecurityIdentifier)))
                {
                    if (r.AccessControlType == AccessControlType.Deny &&
                        (r.FileSystemRights & FileSystemRights.Write) != 0 &&
                        r.IdentityReference.Value == SidEveryone.Value)
                        toRemove.Add(r);
                }
                foreach (FileSystemAccessRule r in toRemove)
                    fs.RemoveAccessRuleSpecific(r);
            }
            else
            {
                fs.RemoveAccessRuleSpecific(denyWrite);
                fs.AddAccessRule(denyWrite);
            }
            File.SetAccessControl(path, fs);
            return null;
        }
        catch (Exception ex)
        {
            return ex.Message;
        }
    }

    // ---- SHA256 哈希生成/校验 ----
    public static string HashFile(string path)
    {
        return HashFile(path, null);
    }

    public static string HashFile(string path, Action<int> progress)
    {
        using (SHA256 sha = SHA256.Create())
        using (FileStream fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
        {
            long total = fs.Length;
            byte[] buf = new byte[4 * 1024 * 1024];
            long done = 0;
            int lastPct = -1;
            int n;
            while ((n = fs.Read(buf, 0, buf.Length)) > 0)
            {
                sha.TransformBlock(buf, 0, n, null, 0);
                done += n;
                if (progress != null && total > 0)
                {
                    int pct = (int)(done * 100 / total);
                    if (pct != lastPct)
                    {
                        lastPct = pct;
                        progress(pct);
                    }
                }
            }
            sha.TransformFinalBlock(new byte[0], 0, 0);
            StringBuilder sb = new StringBuilder();
            foreach (byte b in sha.Hash) sb.Append(b.ToString("x2"));
            return sb.ToString();
        }
    }

    public static string GenHashRecord(string path)
    {
        return GenHashRecord(path, null);
    }

    public static string GenHashRecord(string path, Action<int> progress)
    {
        string hash = HashFile(path, progress);
        FileInfo fi = new FileInfo(path);
        string rec = path + ".sha256";
        string line = hash + "  " + fi.Name + "  " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        File.WriteAllText(rec, line + Environment.NewLine, Encoding.UTF8);
        return rec;
    }

    public static string VerifyHash(string path)
    {
        return VerifyHash(path, null);
    }

    public static string VerifyHash(string path, Action<int> progress)
    {
        string rec = path + ".sha256";
        if (!File.Exists(rec)) return "未找到哈希记录：" + rec;
        string cur = HashFile(path, progress);
        string[] lines = File.ReadAllLines(rec);
        foreach (string l in lines)
        {
            if (string.IsNullOrWhiteSpace(l) || l.TrimStart().StartsWith("#")) continue;
            string[] parts = l.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
            {
                if (string.Equals(parts[0], cur, StringComparison.OrdinalIgnoreCase))
                    return "一致：文件未被修改（SHA256 匹配）。\n记录时间: " + (parts.Length >= 3 ? parts[2] : "未知");
                else
                    return "不一致：文件已被修改！\n记录哈希: " + parts[0] + "\n当前哈希: " + cur;
            }
        }
        return "哈希记录格式无效。";
    }
}

// ============ GUI ============
public class MainForm : Form
{
    Panel dropZone;
    Label lblHint, lblInfo;
    Button btnHashGen, btnHashCheck;
    Button btnProtect, btnReadOnly, btnUnprotect, btnCancelHash, btnOpenParent;
    string currentFile;
    BackgroundWorker hashWorker;
    string hashMode;
    bool hashRunning;
    static readonly Color DisabledBack = Color.FromArgb(228, 231, 235);
    static readonly Color DisabledFore = Color.FromArgb(165, 170, 178);

    public MainForm() : this(null) { }

    public MainForm(string initialFile)
    {
        Text = "VHDX 父盘只读保护 v1.7";
        Font = new Font("Microsoft YaHei UI", 10f);
        ClientSize = new Size(620, 560);
        StartPosition = FormStartPosition.CenterScreen;
        BackColor = Color.FromArgb(245, 247, 250);
        FormBorderStyle = FormBorderStyle.FixedSingle;
        MaximizeBox = false;

        Label title = new Label();
        title.Text = "VHDX 父盘只读保护";
        title.Font = new Font("Microsoft YaHei UI", 16f, FontStyle.Bold);
        title.ForeColor = Color.FromArgb(30, 60, 110);
        title.SetBounds(20, 14, 400, 36);
        Controls.Add(title);

        Label sub = new Label();
        sub.Text = "拖入父盘 VHDX：一键只读 + ACL 硬锁 + 哈希校验，防误挂载破坏子盘。";
        sub.ForeColor = Color.FromArgb(90, 100, 115);
        sub.SetBounds(22, 52, 580, 24);
        Controls.Add(sub);

        dropZone = new Panel();
        dropZone.AllowDrop = true;
        dropZone.BorderStyle = BorderStyle.FixedSingle;
        dropZone.BackColor = Color.White;
        dropZone.SetBounds(20, 90, 580, 120);
        dropZone.DragEnter += OnDragEnter;
        dropZone.DragDrop += OnDragDrop;
        dropZone.Click += (s, e) => PickFile();
        Controls.Add(dropZone);

        lblHint = new Label();
        lblHint.Text = "把 .vhdx 文件拖到这里\r\n或点击选择文件";
        lblHint.TextAlign = ContentAlignment.MiddleCenter;
        lblHint.ForeColor = Color.FromArgb(140, 150, 165);
        lblHint.Font = new Font("Microsoft YaHei UI", 13f);
        lblHint.Dock = DockStyle.Fill;
        dropZone.Controls.Add(lblHint);

        lblInfo = new Label();
        lblInfo.AutoSize = false;
        lblInfo.SetBounds(20, 225, 580, 145);
        lblInfo.ForeColor = Color.FromArgb(50, 60, 75);
        lblInfo.Font = new Font("Consolas", 10f);
        Controls.Add(lblInfo);

        btnProtect = MakeButton("一键保护", 20, 395, Color.FromArgb(16, 124, 16), ProtectAll);
        btnReadOnly = MakeButton("设置只读", 210, 395, Color.FromArgb(46, 125, 50), ReadOnlyOnly);
        btnUnprotect = MakeButton("一键解锁", 400, 395, Color.FromArgb(211, 130, 30), UnprotectAll);
        btnHashGen = MakeButton("生成哈希", 20, 445, Color.FromArgb(69, 90, 100), GenHash);
        btnHashCheck = MakeButton("校验哈希", 210, 445, Color.FromArgb(93, 64, 140), CheckHash);
        btnCancelHash = MakeButton("取消计算", 400, 445, Color.FromArgb(180, 60, 60), CancelHash);
        btnCancelHash.Visible = false;
        btnOpenParent = MakeButton("打开父盘", 20, 495, Color.FromArgb(69, 90, 100), OpenParent);
        btnOpenParent.Visible = false;

        hashWorker = new BackgroundWorker();
        hashWorker.WorkerReportsProgress = true;
        hashWorker.WorkerSupportsCancellation = true;
        hashWorker.DoWork += HashWorker_DoWork;
        hashWorker.ProgressChanged += HashWorker_ProgressChanged;
        hashWorker.RunWorkerCompleted += HashWorker_Completed;

        // 拖拽文件到 exe 图标启动时，窗体显示后自动读取该文件
        if (!string.IsNullOrEmpty(initialFile))
        {
            Shown += delegate(object s, EventArgs e) { HandleFile(initialFile); };
        }
    }

    Button MakeButton(string text, int x, int y, Color color, EventHandler handler)
    {
        Button b = new Button();
        b.Text = text;
        b.SetBounds(x, y, 180, 40);
        b.Font = new Font("Microsoft YaHei UI", 11f, FontStyle.Bold);
        b.BackColor = color;
        b.ForeColor = Color.White;
        b.FlatStyle = FlatStyle.Flat;
        b.Enabled = false;
        b.Tag = color;
        b.Click += handler;
        Controls.Add(b);
        return b;
    }

    void OnDragEnter(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop))
            e.Effect = DragDropEffects.Copy;
        else
            e.Effect = DragDropEffects.None;
    }

    void OnDragDrop(object sender, DragEventArgs e)
    {
        string[] files = e.Data.GetData(DataFormats.FileDrop) as string[];
        if (files != null && files.Length > 0)
            HandleFile(files[0]);
    }

    void PickFile()
    {
        OpenFileDialog dlg = new OpenFileDialog();
        dlg.Filter = "虚拟磁盘 (*.vhdx;*.vhd)|*.vhdx;*.vhd|所有文件 (*.*)|*.*";
        if (dlg.ShowDialog() == DialogResult.OK)
            HandleFile(dlg.FileName);
    }

    void ApplyButtonStyle(Button b, bool enabled)
    {
        if (enabled)
        {
            b.Enabled = true;
            b.BackColor = (Color)b.Tag;
            b.ForeColor = Color.White;
        }
        else
        {
            b.Enabled = false;
            b.BackColor = DisabledBack;
            b.ForeColor = DisabledFore;
        }
    }

    void UpdateButtons(VhdxLockApp.Analysis a)
    {
        bool usable = a != null && a.Ok && !a.IsChild;
        bool ro = usable && a.IsReadOnly;
        bool acl = usable && a.HasAclLock;
        bool busy = hashRunning;
        ApplyButtonStyle(btnProtect, usable && !busy && !(ro && acl));
        ApplyButtonStyle(btnReadOnly, usable && !busy && !ro);
        ApplyButtonStyle(btnUnprotect, usable && !busy && (ro || acl));
        ApplyButtonStyle(btnHashGen, usable && !busy);
        ApplyButtonStyle(btnHashCheck, usable && !busy && File.Exists(currentFile + ".sha256"));
        bool isChild = a != null && a.Ok && a.IsChild;
        btnOpenParent.Visible = isChild;
        ApplyButtonStyle(btnOpenParent, isChild && !busy);
    }

    void HandleFile(string path)
    {
        if (hashRunning)
        {
            MessageBox.Show(this, "正在计算哈希，请等待完成或先点击“取消计算”。", "操作中", MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }
        currentFile = path;
        VhdxLockApp.Analysis a = VhdxLockApp.Analyze(path);
        if (!a.Ok)
        {
            ShowInfo(Color.FromArgb(198, 40, 40), "解析失败：" + a.Error);
            UpdateButtons(a);
            return;
        }

        StringBuilder sb = new StringBuilder();
        sb.AppendLine("文件: " + a.FilePath);
        sb.AppendLine("格式: " + a.Format + "    大小: " + (a.FileSize / 1048576.0).ToString("0.#") + " MB");
        sb.AppendLine("卷文件系统: " + a.VolumeFs);
        sb.AppendLine("--------------------------------------------------");

        if (a.IsChild)
        {
            sb.AppendLine("检测结果: 这是【子盘（差分磁盘）】");
            sb.AppendLine("不能对子盘设置保护！请拖入父盘 VHDX。");
            if (!string.IsNullOrEmpty(a.ParentPath))
                sb.AppendLine("父盘路径: " + a.ParentPath);
            ShowInfo(Color.FromArgb(198, 40, 40), sb.ToString());
            UpdateButtons(a);
            lblHint.Text = "检测到子盘，已阻止设置。可点击“打开父盘”定位父盘。";
            return;
        }

        sb.AppendLine("检测结果: 这是【父盘】");
        if (a.IsReadOnly)
            sb.AppendLine("只读属性: 已设置只读保护");
        else
            sb.AppendLine("只读属性: 读写（未保护）");

        if (a.HasAclLock)
            sb.AppendLine("ACL 硬锁: 已启用（拒绝 Everyone 写入）");
        else
            sb.AppendLine("ACL 硬锁: 未启用");

        UpdateButtons(a);

        if (a.IsReadOnly && a.HasAclLock)
        {
            ShowInfo(Color.FromArgb(30, 120, 60), sb.ToString());
            lblHint.Text = "父盘已双重保护（只读 + ACL 硬锁）。";
        }
        else if (a.IsReadOnly || a.HasAclLock)
        {
            ShowInfo(Color.FromArgb(200, 140, 30), sb.ToString());
            lblHint.Text = "父盘部分保护中，点击“一键保护”补齐缺失项。";
        }
        else
        {
            ShowInfo(Color.FromArgb(200, 100, 20), sb.ToString());
            lblHint.Text = "父盘未保护，建议：只读 + ACL 硬锁 + 哈希。";
        }

        if (a.VolumeFs != "NTFS")
            MessageBox.Show(this, "提示：当前文件所在卷为 " + a.VolumeFs + "，该文件系统可能不保留只读属性。\n建议将父盘放在 NTFS 卷上，只读保护才能在其它电脑上持续生效。", "卷文件系统提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
    }

    void ProtectAll(object s, EventArgs e)
    {
        if (string.IsNullOrEmpty(currentFile)) return;
        VhdxLockApp.Analysis a = VhdxLockApp.Analyze(currentFile);
        if (!a.Ok || a.IsChild) return;
        bool changed = false;
        if (!a.IsReadOnly)
        {
            string errRo = VhdxLockApp.SetReadOnly(currentFile, true);
            if (errRo != null)
            {
                MessageBox.Show(this, "设置只读失败：" + errRo, "操作失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            changed = true;
        }
        a = VhdxLockApp.Analyze(currentFile);
        if (!a.HasAclLock)
        {
            string errAcl = VhdxLockApp.SetAclLock(currentFile, true);
            if (errAcl != null)
            {
                MessageBox.Show(this, "设置 ACL 硬锁失败：" + errAcl, "操作失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            changed = true;
        }
        if (changed)
            MessageBox.Show(this, "已一键完成完整保护（先只读 → 后 ACL 硬锁）。\n建议点击“生成哈希”记录当前指纹，便于日后校验。", "操作成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
        else
            MessageBox.Show(this, "父盘已是完整保护状态（只读 + ACL 硬锁）。", "提示", MessageBoxButtons.OK, MessageBoxIcon.Information);
        HandleFile(currentFile);
    }

    void UnprotectAll(object s, EventArgs e)
    {
        if (string.IsNullOrEmpty(currentFile)) return;
        VhdxLockApp.Analysis a = VhdxLockApp.Analyze(currentFile);
        if (!a.Ok || a.IsChild) return;
        bool changed = false;
        if (a.HasAclLock)
        {
            string errAcl = VhdxLockApp.SetAclLock(currentFile, false);
            if (errAcl != null)
            {
                MessageBox.Show(this, "解除 ACL 硬锁失败：" + errAcl, "操作失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            changed = true;
        }
        if (a.IsReadOnly)
        {
            string errRo = VhdxLockApp.SetReadOnly(currentFile, false);
            if (errRo != null)
            {
                MessageBox.Show(this, "解除只读失败：" + errRo, "操作失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
                return;
            }
            changed = true;
        }
        MessageBox.Show(this, changed ? "已一键解除全部保护（先 ACL → 后只读）。" : "父盘当前没有任何保护。", "操作成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
        HandleFile(currentFile);
    }

    void ReadOnlyOnly(object s, EventArgs e)
    {
        if (string.IsNullOrEmpty(currentFile)) return;
        string err = VhdxLockApp.SetReadOnly(currentFile, true);
        if (err != null)
        {
            MessageBox.Show(this, "设置失败：" + err, "操作失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
            return;
        }
        MessageBox.Show(this, "已设置只读属性（未启用 ACL 硬锁）。\n如需完整保护，请再点击“一键保护”补齐 ACL。", "操作成功", MessageBoxButtons.OK, MessageBoxIcon.Information);
        HandleFile(currentFile);
    }

    void OpenParent(object s, EventArgs e)
    {
        if (string.IsNullOrEmpty(currentFile)) return;
        VhdxLockApp.Analysis a = VhdxLockApp.Analyze(currentFile);
        if (!a.Ok) return;
        if (string.IsNullOrEmpty(a.ParentPath) || !File.Exists(a.ParentPath))
        {
            MessageBox.Show(this, "父盘文件不存在：" + a.ParentPath, "无法打开", MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }
        try
        {
            Process.Start("explorer.exe", "/select,\"" + a.ParentPath + "\"");
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "打开父盘目录失败：" + ex.Message, "操作失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    void GenHash(object s, EventArgs e)
    {
        if (string.IsNullOrEmpty(currentFile) || hashRunning) return;
        hashMode = "gen";
        StartHash();
    }

    void CheckHash(object s, EventArgs e)
    {
        if (string.IsNullOrEmpty(currentFile) || hashRunning) return;
        hashMode = "check";
        StartHash();
    }

    void StartHash()
    {
        hashRunning = true;
        lblHint.Text = hashMode == "gen" ? "正在生成哈希..." : "正在校验哈希...";
        lblInfo.Text = "文件较大时请耐心等待，可点击“取消计算”中止。";
        btnCancelHash.Visible = true;
        btnCancelHash.Enabled = true;
        UpdateButtons(VhdxLockApp.Analyze(currentFile));
        hashWorker.RunWorkerAsync(currentFile);
    }

    void CancelHash(object s, EventArgs e)
    {
        if (hashRunning) hashWorker.CancelAsync();
    }

    void HashWorker_DoWork(object sender, DoWorkEventArgs e)
    {
        BackgroundWorker w = (BackgroundWorker)sender;
        string path = (string)e.Argument;
        string mode = hashMode;
        try
        {
            string hash = VhdxLockApp.HashFile(path, delegate(int p)
            {
                if (w.CancellationPending) throw new OperationCanceledException();
                w.ReportProgress(p);
            });
            if (mode == "gen")
            {
                string rec = path + ".sha256";
                FileInfo fi = new FileInfo(path);
                string line = hash + "  " + fi.Name + "  " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
                File.WriteAllText(rec, line + Environment.NewLine, Encoding.UTF8);
                e.Result = "哈希记录已生成：\n" + rec;
            }
            else
            {
                string rec = path + ".sha256";
                if (!File.Exists(rec))
                {
                    e.Result = "未找到哈希记录：" + rec;
                    return;
                }
                string[] lines = File.ReadAllLines(rec);
                string res = "不一致：文件已被修改！\n当前哈希: " + hash;
                foreach (string l in lines)
                {
                    if (string.IsNullOrWhiteSpace(l) || l.TrimStart().StartsWith("#")) continue;
                    string[] parts = l.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                    if (parts.Length >= 2 && string.Equals(parts[0], hash, StringComparison.OrdinalIgnoreCase))
                    {
                        res = "一致：文件未被修改（SHA256 匹配）。\n记录时间: " + (parts.Length >= 3 ? parts[2] : "未知");
                        break;
                    }
                }
                e.Result = res;
            }
        }
        catch (OperationCanceledException)
        {
            e.Result = "CANCEL";
        }
        catch (Exception ex)
        {
            e.Result = "ERR:" + ex.Message;
        }
    }

    void HashWorker_ProgressChanged(object sender, ProgressChangedEventArgs e)
    {
        lblHint.Text = (hashMode == "gen" ? "正在生成哈希" : "正在校验哈希") + " ... " + e.ProgressPercentage + "%（点击“取消计算”可中止）";
    }

    void HashWorker_Completed(object sender, RunWorkerCompletedEventArgs e)
    {
        hashRunning = false;
        btnCancelHash.Visible = false;
        btnCancelHash.Enabled = false;
        string res = e.Result as string;
        if (res == "CANCEL")
        {
            lblHint.Text = "已取消计算。";
        }
        else if (res != null && res.StartsWith("ERR:"))
        {
            MessageBox.Show(this, res.Substring(4), "操作失败", MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        else
        {
            bool ok = res != null && (res.StartsWith("一致") || res.StartsWith("哈希记录已生成"));
            MessageBox.Show(this, res, hashMode == "gen" ? "操作成功" : "哈希校验", MessageBoxButtons.OK, ok ? MessageBoxIcon.Information : MessageBoxIcon.Warning);
        }
        HandleFile(currentFile);
    }

    void ShowInfo(Color c, string text)
    {
        lblInfo.ForeColor = c;
        lblInfo.Text = text;
    }
}
