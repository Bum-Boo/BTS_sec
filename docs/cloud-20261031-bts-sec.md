# BTS Sec 클라우드 점검 보고서 (2026-10-31)

- 기준 브랜치: `feature/security-auditing-toolkit` (`b3a7dbb`)
- 작업 브랜치: `claude/audit-toolkit-fixtures-rh1ory`
- 환경: Linux VM, Node v22.23.4, npm 10.9.9, Python 3 (pip-audit 2.10.1은 scratch venv에만 설치)
- 저장소에 AGENTS.md / CLAUDE.md / CONTRIBUTING 은 없음. README 와 `docs/` 만 확인함.
- 모든 픽스처는 합성 데이터임. 토큰 모양 문자열은 테스트 실행 시 문자열 연결로 만들어서 저장소에 자격 증명처럼 보이는 리터럴이 들어가지 않음. 웹 점검은 127.0.0.1 목(mock) 서버로만 수행함.

## 1. 요약

| 측정 | 수정 전 (TP / FP / FN) | 수정 후 (TP / FP / FN) |
| --- | --- | --- |
| 픽스처 프로젝트 6개 (`tests/fixtures/benchmark-projects.ts`, 기대 52건) | 32 / 18 / 20 | 52 / 0 / 0 |
| 독립 작성 단일 라인 케이스 95개 (`tests/fixtures/heldout-cases.json`, 기대 57건) | 41 / 16 / 16 | 57 / 0 / 0 |
| URL 스캐너 목 서버 (취약 11건 기대 + 하드닝된 SPA) | 9 / 2 / 2 | 11 / 0 / 0 |
| 자체 `src/` 스캔 | 2건 | 3건 |

- 픽스처 수치는 규칙을 고친 사람이 직접 만든 픽스처 기준이라 과적합 여지가 있음. 그래서 규칙 구현을 보지 않은 서브에이전트가 규칙 ID와 설명만 보고 단일 라인 케이스를 따로 작성했고, 이 세트에서도 같은 결함 유형(FP 16, FN 16)이 재현됨. 그 뒤 이 세트를 보고 규칙 하나(`code.raw-sql` 혼합 따옴표)를 더 고쳤으므로, 이 세트도 이제는 완전한 홀드아웃이 아님.
- 자체 스캔 결과는 모두 `src/code-scanner/custom-rules.ts` 안의 정규식 리터럴이 자기 자신에 매칭된 것임 (비이슈).

## 2. 명령과 결과 (전/후)

| 명령 | 수정 전 | 수정 후 |
| --- | --- | --- |
| `npm ci` | 성공 | 성공 (의존성·lockfile 변경 없음) |
| `npm test` (`vitest run`) | 8 files / 9 tests 통과 | 17 files / 32 tests 통과 |
| `npm run lint` (`tsc --noEmit`) | 통과 | 통과 |
| `npm run build` (`tsc`) | 통과 | 통과 |
| `npm run scan -- scan --dir ./src --profile vibe-risk --out reports/local` (README 문서 그대로) | `Unknown argument: --dir`, exit 1 | README 를 실제 CLI 에 맞게 수정 (아래 F12) |
| `npm run scan -- --target <dir> --out <dir>` | 성공 | 성공 |
| `npx tsx <scratch>/bench.ts` (픽스처 점수 출력) | TP 32 / FP 18 / FN 20 | TP 52 / FP 0 / FN 0 |

수정 전 수치는 기준 브랜치의 `git worktree` 에 최종 픽스처를 복사해서 같은 하네스로 측정함.

## 3. 발견 사항

분류: **검증된 결함**(재현 후 수정 + 회귀 테스트), **정적 위험**(코드상 위험이지만 이 VM 에서 재현하지 않았거나 수정하지 않음), **이미 커버됨**, **비이슈**.

### 검증된 결함 (수정함)

- **F1. `.env`·`.npmrc` 등 dotfile 이 아예 스캔되지 않음.** `path.extname(".env")` 이 `""` 이라 확장자 허용 목록에 걸리지 않았음 (기존 `src/utils/fs.ts:59`). 비밀값이 가장 많이 있는 파일이 누락됨. → `fileTypeKey()` 추가 (`src/utils/fs.ts:75`). 테스트: `tests/file-walk.test.ts`.
- **F2. 비밀값 탐지의 누락/오탐.** 기존 패턴(`src/secret-scanner/internal-secret-scanner.ts:8`)은 키워드 앞에 단어 경계를 요구해서 `OPENAI_API_KEY`, `DATABASE_PASSWORD`, `STRIPE_SECRET_KEY`, JSON 키 `"client_secret": ...` 를 놓쳤고, 따옴표가 선택이라 `const password = req.body.password` 나 `= process.env.API_KEY` 를 high 심각도 비밀값으로 보고했음. `.pem`·`.key` 파일도 스캔 대상이 아니었음. → 공용 매처 `src/secret-scanner/secret-patterns.ts:25`, `:46`. 따옴표 없는 값은 `.env`/`.ini`/YAML 류에서만 리터럴로 취급하고 플레이스홀더는 제외함. Stripe/Slack/Google 토큰 모양을 추가함. `code.hardcoded-secret` 도 같은 매처를 씀 (`src/code-scanner/custom-rules.ts:36`). 테스트: `tests/secret-patterns.test.ts`, 벤치마크.
- **F3. 리포트 증거 마스킹 누락 (비밀값 유출).** 공백이 들어간 따옴표 값(`password: "fixture horse battery staple"`)과 JSON 형태 키는 마스킹되지 않은 채 `report.md/json/sarif` 에 그대로 기록됐음 (기존 `src/scanner-core/redaction.ts:1`). → `src/scanner-core/redaction.ts:4`. 테스트: `tests/secret-redaction.test.ts`.
- **F4. Linux/macOS 에서 외부 도구를 하나도 찾지 못함.** `commandExists` 가 셸 빌트인 `command` 를 셸 없이 spawn 해서 항상 ENOENT 가 났음 (기존 `src/utils/command.ts:71`). `commandExists("node")` 도 false 였음. → PATH 를 직접 탐색하도록 수정 (`src/utils/command.ts:72`). 테스트: `tests/command-exists.test.ts`. 참고로 이 수정 때문에 `--include-external` 이 실제로 도구를 실행하게 되므로 F5 가 중요해짐.
- **F5. pip-audit 어댑터가 대상 코드를 실행함 (안전성 위반).** `pip-audit -r requirements.txt -f json -l` 은 요구사항을 임시 venv 에 pip 로 설치해서 해석하기 때문에 로컬/sdist 요구사항의 `setup.py` 가 실행됨. 마커 파일을 쓰는 무해한 `setup.py` 로 재현했음 (기존 `src/dependency-scanner/pip-audit-adapter.ts:41`). `--disable-pip --no-deps` 를 쓰면 마커가 생기지 않고, `requests==2.19.0` 에서 취약점 10건은 그대로 탐지됨. → `src/dependency-scanner/pip-audit-adapter.ts:45`. 핀 고정이 안 된 요구사항은 이제 조용히 빈 결과를 내는 대신 어댑터 실패로 보고함. 테스트: `tests/adapter-arguments.test.ts`.
- **F6. SBOM 이 대상 밖의 파일을 읽고, 잘못된 JSON 하나로 스캔 전체가 중단됨.** `requirements.txt` 가 대상 밖 파일을 가리키는 심볼릭 링크이면 그 내용이 `sbom.cdx.json` 과 `report.json` 에 기록됐음. 잘못된 `package.json` 은 `generateSbom` 에서 예외를 던져 스캔이 끝났음 (기존 `src/dependency-scanner/sbom.ts:47`, 호출부 `src/scanner-core/orchestrator.ts:32` 는 어댑터 보호 밖에 있음). → realpath 가 대상 안에 있을 때만 읽고, 실패한 매니페스트는 SBOM 메타데이터에 기록함 (`src/dependency-scanner/sbom.ts:54`). 테스트: `tests/sbom-safety.test.ts`.
- **F7. 코드 규칙 오탐 (깨끗한 코드에서 측정).** `src/code-scanner/custom-rules.ts:37-59`.
  - `code.shell-execution`: `/re/.exec(s)`, Mongoose `query.exec()` 를 셸 실행으로 보고함.
  - `code.eval-usage`: PyTorch `model.eval()` 을 보고함.
  - `code.weak-jwt`: 올바른 사용법인 `jwt.verify()` 와 키·알고리즘을 지정한 PyJWT `jwt.decode()` 를 보고함. 이제 JS 는 decode/none/ignoreExpiration, Python 은 `verify_signature: False`/none 만 봄.
  - `code.raw-sql`: `f"Deleted user {id}"` 같은 로그 문자열을 SQL 로 보고함. 이제 SQL 문 구조(SELECT…FROM, INSERT INTO, UPDATE…SET, DELETE FROM)를 요구함.
  - `code.missing-authorization`: `requireAuth`/`authenticate` 미들웨어가 있는 라우트도 보고함.
  - `code.dangerous-logging`: `console.log("Token refreshed")` 처럼 메시지 텍스트에만 키워드가 있어도 보고함.
  - `code.ssrf-user-controlled-url` / `code.path-traversal`: 고정 URL 에 `{ body: ... }` 옵션을 넘기거나 콜백 인자 이름이 `body` 이면 보고함. 이제 첫 번째 인자만 봄.
  - `code.next-dangerous-html`: `DOMPurify.sanitize()` 를 거친 값도 보고함 (판단이 필요한 휴리스틱 변경임).
- **F8. 코드 규칙 누락.** `readFileSync`(path-traversal), `cors({ origin: "*" })`, `.csrf(AbstractHttpConfigurer::disable)`(Spring Security 6 표준 방식), `spawn(..., { shell: true })`, Python `"..." % x` / `.format()` SQL, 혼합 따옴표 SQL 연결을 추가함.
- **F9. 백업 노출 오탐.** `/backup.zip`·`/backup.tar.gz` 마커에 `html` 이 들어 있어서 모든 경로에 index.html 을 200 으로 주는 SPA 가 항상 "백업 노출"로 보고됐음 (기존 `src/web-scanner/exposure-checker.ts:16`). gzip 시그니처는 본문을 UTF-8 로 디코딩하면서 0x8b 가 U+FFFD 로 바뀌어 한 번도 매칭되지 않았음. → `src/web-scanner/exposure-checker.ts:19`.
- **F10. 쿠키 플래그 점검 누락.** `Headers.forEach` 가 Set-Cookie 를 하나씩 넘겨줘서 마지막 쿠키만 남았음 (기존 `src/web-scanner/http-client.ts:57`). 플래그도 부분 문자열로 확인해서 `Path=/secure-area` 를 Secure 로 판정했음 (기존 `src/web-scanner/cookie-checker.ts:34`). → `getSetCookie()` 사용 (`src/web-scanner/http-client.ts:61`), 속성 이름 비교 (`src/web-scanner/cookie-checker.ts:37`). 테스트: `tests/web-scanner-fixtures.test.ts`.
- **F11. Semgrep 메트릭 명시적 비활성화.** 로컬 설정만 쓰므로 기본값에서도 전송되지 않을 가능성이 높지만, 방어적으로 `--metrics=off` 를 추가함 (`src/code-scanner/semgrep-adapter.ts:61`). Semgrep 은 이 VM 에 설치하지 않았으므로 인자 목록만 테스트로 확인함.
- **F12. README 빠른 시작 명령이 동작하지 않음.** `scan --dir/--url --profile vibe-risk --authorization-confirmation` 은 이 브랜치 CLI 에 없음. `agent-fix-prompt.md` 도 생성되지 않음. 이 기능들은 원격의 `feature/vibe-risk-toolkit`, `feature/agent-fix-prompts` 브랜치에 있음(읽기 전용으로 확인만 함). → 루트 README 를 실제 플래그에 맞추고 브랜치 차이와 `--include-external` 의 네트워크 동작을 명시함.

### 정적 위험 (수정하지 않음)

- **S1. Windows 셸 경유 실행.** `runCommand` 가 Windows 에서 `shell: true` 로 인자를 그대로 넘김 (`src/utils/command.ts:22`). 디렉터리 이름에 `&` 같은 셸 메타문자가 있으면 명령 주입이 가능할 수 있음. 이 VM 에서는 검증할 수 없음.
- **S2. 대상이 제어하는 외부 도구 설정.** `npm audit` 은 대상 디렉터리를 cwd 로 실행되므로 (`src/dependency-scanner/npm-audit-adapter.ts:35`) 대상의 `.npmrc` 가 registry 를 바꾸면 의존성 목록이 그 호스트로 전송될 수 있음. Semgrep 은 대상의 `.semgrep.yml` 을 씀 (`src/code-scanner/semgrep-adapter.ts:47`). Gitleaks 는 대상의 `.gitleaks.toml` 을 자동으로 읽을 수 있음. 대상이 결과를 숨길 수 있다는 뜻임 (`--include-external` 사용 시에만 해당).
- **S3. 예측 가능한 임시 파일 경로.** Gitleaks/ZAP 리포트 경로가 `os.tmpdir()` + `Date.now()` 임 (`src/secret-scanner/gitleaks-adapter.ts:38`, `src/web-scanner/zap-adapter.ts:38`). 공유 호스트에서는 심볼릭 링크 경쟁 위험이 있음. `fs.mkdtemp` 사용을 권장함.
- **S4. 탐지 한계.** 규칙이 줄 단위라 여러 줄에 걸친 호출이나 설정은 놓침. `cp.exec` 이외의 별칭으로 가져온 exec 도 놓침. 비밀값이 코드 파일에 하드코딩되면 `code.hardcoded-secret` 과 `secret.detected` 가 같은 줄에 중복으로 보고됨. `code.unsafe-upload` 는 모든 `upload.single()` 을 보고하는 리뷰 신호임. 확장자가 없는 `id_rsa` 같은 키 파일은 스캔하지 않음.
- **S5. 문서와 코드 불일치.** `docs/readme/*` (en/ko/zh-CN/ja) 와 루트 README 의 "What It Checks" 일부(OpenAPI, Supabase/Firebase, vibe-risk, EPSS, 크롤러 옵션)는 이 브랜치에 구현되어 있지 않음. 루트 README 에 안내만 추가했고 번역본은 손대지 않음.

### 이미 커버됨 (확인함)

- URL 스캔은 `--confirm-authorization` 이 필요하고, 자격 증명이 포함된 URL 은 거부되며, 같은 출처만 허용됨 (`tests/target-validation.test.ts`). 목 서버로 GET/HEAD/OPTIONS 만 쓰는 것과, 다른 출처로의 302 리다이렉트를 따라가지 않는 것을 추가로 확인함 (`tests/web-scanner-fixtures.test.ts`).
- 파일 워커는 심볼릭 링크를 따라가지 않음 (회귀 테스트 추가, `tests/file-walk.test.ts`).
- 기본 디렉터리 스캔은 `fetch` 를 호출하지 않고 하위 프로세스를 만들지 않으며, `postinstall`/`setup.py` 를 실행하지 않음 (가드 테스트 `tests/default-scan-isolation.test.ts`).
- Nuclei 템플릿 허용 목록, 파괴적 모드 거부, 어댑터 실패 격리, 레이트 리미터, TruffleHog `--no-verification` 은 기존 테스트나 코드로 확인함. `--refresh-kev` 는 명시적으로 켰을 때만 cisa.gov 에 접속함 (`src/knowledge-base/kev.ts:4`).

### 비이슈

- 자체 `src/` 스캔 결과 3건은 규칙 정의 파일의 정규식 텍스트가 자기 자신에 매칭된 것임.

## 4. 이 VM 에서 검증하지 못한 것

- Windows/macOS 동작 (특히 S1, `where` 경로, macOS 의 `/usr/bin/command`).
- Semgrep, Gitleaks, TruffleHog, Trivy, OSV-Scanner, Nuclei, OWASP ZAP 실제 실행. 이 도구들은 설치하지 않았고 인자와 파싱만 목으로 확인함. pip-audit 만 scratch venv 에서 실제로 실행함 (PyPI/OSV 조회 포함).
- 실제 외부 서비스와 실제 웹사이트. URL 스캔은 127.0.0.1 목 서버로만 확인했고, `--refresh-kev` 는 실행하지 않음.
- HTML 리포트의 브라우저 렌더링 (GUI).

## 5. 소유자를 위한 다음 단계

1. 이 브랜치를 리뷰한 뒤 `feature/security-auditing-toolkit` 으로 병합할지 정함. `feature/vibe-risk-toolkit` 에도 같은 `src/utils/fs.ts`, `redaction.ts`, `command.ts`, pip-audit 코드가 있다면 F1·F3·F4·F5 를 그쪽에도 옮겨야 함.
2. 문서를 하나로 정리함: 번역 README 를 이 브랜치 CLI 에 맞추거나, vibe-risk 브랜치를 병합한 뒤 README 를 다시 검증함.
3. S2 대응: `npm audit --registry=https://registry.npmjs.org/` 강제 여부, Semgrep/Gitleaks 에 대상 설정 대신 도구 자체 설정을 쓸지 결정함.
4. S3 를 `fs.mkdtemp` 로 바꾸고, Windows 에서 S1 을 재현해 봄 (`shell: false` + `.cmd` 확장자 처리).
5. 실제 Semgrep/Gitleaks/Trivy 를 설치한 CI 잡에서 `--include-external` 통합 테스트를 돌림.
6. 줄 단위 한계(S4)를 줄이려면 JS/TS 는 AST 기반 규칙(Semgrep 로컬 규칙 동봉)을 검토함.
