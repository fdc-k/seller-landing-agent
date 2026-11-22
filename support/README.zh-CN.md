# Windows 临时远程支持入口

`windows-ssh.ps1` 是独立的 SSH 支持引导器，供卖家在自己的美国 Windows 电脑上运行。它先生成本机密钥和安全 JSON 回执，再由管理员把回执里的**隧道公钥**登记到固定美国中转。登记之前回执状态始终是 `pendingRelayAuthorization`；启动任务不代表远程已经接通。

需要 Windows 10 1809 / Windows 11、64 位管理员 PowerShell 5.1+，以及当前卖家自己的本地管理员账号。通过当前 SID 查询并核对本地账号，支持关联 Microsoft 账号的本地用户；不会按登录显示名称或域前缀猜测身份。用户名支持 Unicode 字母、数字、空格、下划线、句点、连字符和单引号，拒绝 SSH 通配符及配置控制字符；域和 Entra 账号仍不支持。安装 Windows 自带 OpenSSH 可选功能可能需要 Windows Update、较长等待或重启；失败会明确报错，不下载第三方二进制。

管理员从固定 Git 提交生成一条命令，先在内存校验脚本 SHA256 再执行，并私下填入这些**公开参数**：

| 参数 | 内容 |
| --- | --- |
| `AccountId` | 固定账号 UUID / 小写安全标识 |
| `RelayHost` / `RelayPort` | 固定美国中转公网 IPv4 / SSH 端口，默认 22 |
| `RelayUser` / `ReversePort` | 该机器专用中转 Unix 用户 / 独占反向端口 |
| `RelayHostKey` | 经管理员独立核验的中转 Ed25519 **公钥**，严格固定 |
| `AdminPublicKey` | 每账号独立的控制端 Ed25519 **公钥** |
| `LocalPort` | 本机回环支持端口，默认 29422 |
| `IncludePublicIp` | 可选：向 ipify HTTPS 查询出口 IP；失败写明 `unavailable` |

脚本和命令都不需要 PAT、Windows 密码或私钥。不要把控制端私钥传到卖家电脑、中转或公开仓库。生成的本机主机私钥、隧道私钥只留在 `%ProgramData%\WAO\SellerSupport`。JSON 回执可私下发给管理员，含账号、稳定安装 UUID、Windows 安装身份摘要、机器名、本地用户名、时区、主机公钥/指纹、隧道公钥、中转端点及待登记状态；回执不包含私钥。`machineId` 是安装 UUID；`deviceFingerprint` 是 Windows MachineGuid 的 SHA256 摘要，用于拒绝跨 Windows 安装复制状态，两者都不是物理所有权证明。

引导器只让独立 sshd 监听 `127.0.0.1:29422`（或指定端口），只准当前本地用户以登记公钥认证，禁止 SSH 端口/代理转发。两个 SYSTEM 计划任务在开机后分别运行隔离 sshd 和自动重连隧道，无需用户保持登录。机器需开机、不休眠，并能主动访问中转 SSH。配置、脚本、密钥目录仅 SYSTEM 和 Administrators 可访问，遇到不可信已有目录、重解析点、冲突任务、异账号或不同绑定会拒绝覆盖。

不会启动或重配置全局 `sshd`，不会修改它的配置或默认 shell，也不会为支持端口开放防火墙。Windows 安装 OpenSSH.Server 功能本身可能创建默认端口 22 防火墙规则；脚本只移除本次安装新建、此前不存在的 `OpenSSH-Server-In-TCP` 规则，保留原有规则。可选功能本身仍留在系统中。

管理员收到回执后，先核对账号、控制端公钥指纹、中转和主机公钥；把隧道公钥限制为仅能监听 `127.0.0.1:<ReversePort>` 的反向转发密钥，禁止该中转账号的交互 shell、代理和其他转发。应在中转独立账号上配置 `AllowTcpForwarding remote`、`GatewayPorts no`、专用 `PermitListen`，并通过公钥选项禁止 PTY/agent/X11 等权限，不能只依赖客户端参数。随后从管理员机器经中转连接该回环端口，使用账号专属控制端私钥，并将回执的 Windows 主机公钥固定到独立 known_hosts。实际 SSH 验证成功后才标记可远程支持。

卸载时，在卖家电脑的管理员 PowerShell 执行：

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "$env:ProgramData\WAO\SellerSupport\uninstall.ps1" -Uninstall
```

卸载先核验任务归属，停止/注销本工具两个任务，再逐个删除本工具已知文件和专用目录；不递归删除父目录、不卸载 OpenSSH、不改全局 SSH。若进程仍运行，会保留状态并要求重启后重试。管理员还需从中转撤销该机器隧道公钥。相同安装命令可恢复同一绑定；换账号、中转、公钥或端口需先卸载并撤销旧钥。

实现依据：[Microsoft Windows OpenSSH 配置](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh-server-configuration)、[Windows OpenSSH 安装前提与可选功能](https://learn.microsoft.com/en-us/windows-server/administration/openssh/openssh_install_firstuse)。使用 `sshd -t` 和 `sshd -T` 校验目标机的实际配置；不使用 Windows 不支持的 `StrictModes`、`X11Forwarding`、`PidFile` 等指令。静态语法/审查通过不代表已经在真实卖家机器完成安装或连通测试。

账号解析的离线回归测试：在仓库根目录运行 `powershell.exe -NoProfile -ExecutionPolicy Bypass -File test/windows-support-identity.test.ps1`。测试从语法树提取账号校验与 UTF8 读取函数，使用模拟账号记录和无害 PowerShell 子进程验证 Unicode 输出及双管道读取；不执行引导器、不安装功能、不启动任务或 sshd。
