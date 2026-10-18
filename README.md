# powershell-mcp-security

A Claude Code skill that audits and hardens the network security of a Windows, Linux or macOS machine through [PowerShell.MCP](https://github.com/yotsuda/PowerShell.MCP) — **with the person at that machine watching every command**.

- **Read-only first.** Inside (effective settings, not just config files) and outside (what the network sees), cross-checked.
- **Fixes only with your approval**, in an order that cannot lock you out.
- **Verified** from outside and again after a reboot — where settings quietly revert.

<img width="1672" height="941" alt="image" src="https://github.com/user-attachments/assets/fc9c9d41-5cfd-4771-8741-54f344f18617" />

## Requirements

- **Your machine**: Claude Code, PowerShell 7.4+ and PowerShell.MCP 1.16.0 or later. In PowerShell 7:
  ```powershell
  Install-Module PowerShell.MCP
  Register-PwshToClaudeCode
  ```
- **The machine to audit** (if it is not your machine): PowerShell 7.4+ and the **same version** of PowerShell.MCP, and inbound TCP 42777 from your machine. Then, in PowerShell 7 there:
  ```powershell
  Enable-MCPRemoteControl -AllowFrom <your machine's address>
  ```
  Tell Claude the host and the pairing code it prints. If that machine cannot accept inbound connections (NAT, a cloud firewall), Claude can wait on your machine instead and give you an `Enable-MCPRemoteControl -ConnectTo …` line to run there.

Installing PowerShell 7 on a server is itself a change. Remote control is open only while the console runs `Enable-MCPRemoteControl`; end it with `Disable-MCPRemoteControl` or by closing the console. If you would rather not install anything there, the checks under [`checks/`](skills/network-security-audit/checks) are plain commands you can run by hand.

## Install the skill

From the [PowerShell.MCP plugin marketplace](https://github.com/yotsuda/powershell-mcp-plugins):

```
/plugin marketplace add yotsuda/powershell-mcp-plugins
/plugin install powershell-mcp-security@powershell-mcp
```

The skill is then available as `powershell-mcp-security:network-security-audit`. Claude uses it on its own when you ask for a security audit.

## Use

> Audit the network security of this server. Read-only first, and check what is visible from outside. Then fix what you find, with my approval for each change, and verify again after a reboot.

## Contributing

Checks and fixes for more systems are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md).

## Scope

Use it only on machines you own or are authorized to manage. It is not a replacement for continuous monitoring (SOC, EDR); it closes the doors before anyone knocks.

Tested on Ubuntu 24.04 (Hyper-V VM) and Windows 11 (Windows Sandbox). The fix guidance is most complete for Linux; the macOS checks are not yet tested on a real Mac.

## License

[MIT](LICENSE)

---

## 日本語

[PowerShell.MCP](https://github.com/yotsuda/PowerShell.MCP) を通して、AI に Windows・Linux・macOS のマシンのネットワークセキュリティを監査させ、対処まで進めるための Claude Code のスキルです。AI が実行するコマンドは、すべて対象のマシンのコンソールに表示され、そこにいる人が見て止められます。

まず読み取りだけで、中（実際に効いている設定）と外（ネットワークから見える状態）を突き合わせます。変更はあなたの承認を得てから、締め出されない順番で行い、外から、そして再起動後にも確かめ直します。

チェック項目や対処の方法の追加を歓迎します（[CONTRIBUTING.md](CONTRIBUTING.md)）。日本語での Issue・PR も歓迎です。
