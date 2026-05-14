# VibeSec / BTS Sec

> Passive, non-destructive security auditing for vibe-coded and AI-assisted web projects.

[Overview](../../README.md) | [English](README.en.md) | [한국어](README.ko.md) | [中文](README.zh-CN.md) | [日本語](README.ja.md)

VibeSec / BTS Sec 是一个防御性安全审计工具，用于 vibe-coded Web 应用、AI 辅助代码库和已授权的 Web 服务。它关注 AI coding agent、low-code AI app builder、自动生成的认证/数据库/支付流程以及默认公开部署中常见的风险。

默认行为是 passive、non-destructive 检查。日志保留在本地，检测到的 secret 会被 redaction，URL 扫描必须有明确授权确认。

### 快速开始

```bash
npm install
npm run build
vibesec scan --dir ./path/to/project --profile vibe-risk --out reports/local
vibesec scan --api-spec ./openapi.json --out reports/api
```

### 安全模型

- 不执行 exploit
- 不进行 brute force
- 不窃取 credential
- 不发送 destructive payload
- URL 扫描限制在用户提供的 same-origin 范围内
- URL 扫描需要明确的 authorization confirmation
- 报告不会保存 raw secret、token 或 response body

### 演示流程

1. 运行 `npm install`。
2. 运行 `npm run build`。
3. 对你拥有或被授权评估的本地项目运行 `npm run scan -- scan --dir "<project-path>" --profile vibe-risk --out reports/local`。
4. 如果有 OpenAPI 文件，加入 `--api-spec "<openapi-path>"`。
5. 在浏览器中打开 `reports\local\report.html`，查看 `Coverage & Known Gaps` 和 `Findings`。
