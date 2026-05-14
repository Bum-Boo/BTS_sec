# VibeSec / BTS Sec

> Passive, non-destructive security auditing for vibe-coded and AI-assisted web projects.

[Overview](../../README.md) | [English](README.en.md) | [한국어](README.ko.md) | [中文](README.zh-CN.md) | [日本語](README.ja.md)

VibeSec / BTS Sec는 vibe-coded 웹 애플리케이션, AI-assisted 코드베이스, 승인된 웹 서비스를 위한 방어적 보안 감사 도구입니다. AI 코딩 에이전트, low-code AI app builder, 자동 생성된 인증/데이터베이스/결제 흐름, 기본 공개 배포에서 자주 생기는 위험을 점검합니다.

기본 동작은 passive, non-destructive 검사입니다. 로그는 로컬에 남기고, 감지된 secret은 redaction하며, URL 스캔은 명시적 승인 문구 없이는 실행하지 않습니다.

### 빠른 시작

```bash
npm install
npm run build
vibesec scan --dir ./path/to/project --profile vibe-risk --out reports/local
vibesec scan --api-spec ./openapi.json --out reports/api
```

### 안전 모델

- exploit 실행 없음
- brute force 없음
- credential theft 없음
- destructive payload 없음
- URL 스캔은 사용자가 지정한 same-origin 범위로 제한
- URL 스캔에는 명시적 authorization confirmation 필요
- 보고서에는 raw secret, token, response body를 저장하지 않음

### 데모 흐름

1. `npm install`을 실행합니다.
2. `npm run build`를 실행합니다.
3. 본인 소유 또는 점검 허가를 받은 로컬 프로젝트를 대상으로 `npm run scan -- scan --dir "<project-path>" --profile vibe-risk --out reports/local`을 실행합니다.
4. OpenAPI 파일이 있으면 `--api-spec "<openapi-path>"`를 함께 넣습니다.
5. `reports\local\report.html`을 브라우저에서 열고 `Coverage & Known Gaps`, `Findings`를 확인합니다.
