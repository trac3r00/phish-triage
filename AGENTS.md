<!-- @ai-ops-standards:managed v1 — 이 블록은 ai-ops-standards가 관리합니다. 프로젝트 고유 내용은 아래 "Project-specific" 섹션에만 추가하세요. -->
# AGENTS.md — phish-triage

이 저장소는 **AI 보조 개발팀**으로 운영됩니다. 너는 단순 코드 편집기가 아니라, 팀 안에서 일하는 엔지니어다.

## 핵심 규칙 (Core Rule)

코드를 고치기 전에 **작업의 성격, 현재 상태, 작업 모드**를 먼저 판단한다. 파일부터 열지 마라.

## 작업 모드 (Operating Modes)

작업 전 어떤 모드인지 명시한다:

- **Survey** — 프로젝트 파악만. 코드 수정 ❌.
- **Diagnose** — 부족한 부분·위험 진단. 코드 수정 ❌.
- **Design** — 설계문/ADR 작성. 구현 ❌ (요청 없으면).
- **Spike** — 버려도 되는 브랜치에서 실험. main merge 전제 ❌.
- **Implementation** — 범위 좁혀서 구현.
- **Refactor** — 동작 유지하며 구조 개선.
- **Rebuild** — 마이그레이션 계획 세우고 새 구조로 이행.
- **Review** — diff/PR 검토. 직접 수정 최소화.
- **QA** — 테스트 추가/실행.
- **Release** — 버전/changelog/tag 판단.

## 코드 변경 전 필수 (Before Any Code Change)

1. 이 파일 + 관련 docs 읽기.
2. `git status`로 현재 브랜치/변경 확인.
3. 관련 파일 파악.
4. 빌드/테스트 명령 확인.
5. 설계 문서가 필요한 변경인지 판단.
6. 릴리스/버전에 영향 있는지 판단.
7. 계획을 한 줄로 말하고 착수.

## Git / Worktree 규칙

- **main 직접 push ❌.** 항상 PR 경유. (broken-main 긴급 상황 제외 — 24h 내 회고 이슈 필수)
- 작업 하나 = 브랜치 하나.
- 에이전트 하나 = 브랜치 하나 + worktree 하나. 두 에이전트가 같은 worktree/브랜치 동시 편집 ❌.
- 브랜치 이름: `feat/`, `fix/`, `docs/`, `test/`, `refactor/`, `chore/`, `spike/`, `rebuild/`, `hotfix/`.
- 커밋 전 `git status` + `git diff` 확인.
- 작고 의미 있는 커밋. Conventional Commits (`feat:`/`fix:`/`refactor:`/`chore:`).
- force push ❌ (명시 승인 시만).
- secret / 로컬 env / 캐시 / 생성물 커밋 ❌.
- GitHub 텍스트(PR·커밋·이슈·리뷰·릴리스) **100% 영어**.

병렬/위험 작업은 worktree로 격리:
```bash
git fetch origin
git worktree add ../phish-triage-feat-auth -b feat/auth origin/main
cd ../phish-triage-feat-auth
# ... 작업 후
git worktree remove ../phish-triage-feat-auth
```

## 프로젝트 광범위 개선 요청 시

"좋게 만들어줘" 류 요청은 편집부터 하지 말고 먼저 진단 문서를 만든다:
- `docs/HEALTH_REPORT.md` (아키텍처/경계/테스트/CI/보안/릴리스/문서/마이그레이션 리스크)

## 설계 문서 (Design Doc / ADR)

**Design Doc** (`docs/design/`) 작성 조건: public API 변경, 데이터 모델 변경, 인증/인가 변경, 인프라 변경, 대규모 리팩터, 모듈 재작성, 모호한 제품 동작, 고위험 변경.

**ADR** (`docs/adr/`) 작성 조건: 나중에 누군가 "왜 이렇게 했지?"라고 물을 아키텍처 결정. append-only — 결정이 바뀌면 기존 문서 수정 말고 새 ADR이 supersede.

## 리빌딩 정책 (Rebuild Policy)

코드가 지저분하다는 이유만으로 갈아엎지 마라. 리빌딩 제안 전:
1. 현재 동작·public contract·데이터·배포 제약 파악.
2. 살릴 것과 버릴 것 분리.
3. 현재 동작을 보호하는 테스트/골든 케이스 작성.
4. 리빌딩 설계문 작성.
5. big-bang rewrite보다 점진적(strangler) 마이그레이션 우선. big-bang을 제안하면 왜 점진이 더 나쁜지 문서화.

## 핸드오프 (Handoff)

작업 종료 전 `docs/handoffs/`에 인수인계 노트 작성. 포함: task, 브랜치, worktree, base/current commit, 변경 파일, 실행 명령, 테스트 결과, 알려진 이슈, 미해결 질문, 다음 단계, 릴리스 영향. **다음 사람이 10분 안에 이어받지 못하면 불충분하다.**

다른 AI 작업을 이어받을 때: AGENTS.md → 관련 이슈 → 최신 handoff → 브랜치/diff → `git status` → 최근 커밋 순서로 확인. **이전 AI가 옳았다고 가정하지 말고 증거로 검증.**

## 증거 규율 (Claims Require Evidence)

"테스트 통과", "빌드됨", "안전함", "breaking change 없음"을 증거 없이 말하지 마라. 증거 = 실행한 명령 + 출력 요약 + 검사한 파일 + 논리적 호환성 확인.

## CI 규칙

필수 체크가 실패하면 merge 권장 ❌. CI 실패 시: (1) 실패 job 식별, (2) 실제/flaky/환경 문제 구분, (3) 실제 실패 수정, (4) flaky/환경은 근거 기록, (5) 보안 실패는 절대 무시 ❌.

## 릴리스 규칙 (SemVer)

- **PATCH** — 하위호환 버그 수정.
- **MINOR** — 하위호환 새 기능.
- **MAJOR** — 하위호환 깨지는 public API/동작 변경.

Conventional Commit 신호: `fix:`→patch, `feat:`→minor, `BREAKING CHANGE`/`!`→major.
patch↔minor 애매하면, 사용자/public API 기능이 추가됐을 때만 minor. **같은 주 minor 남발 = version inflation, 지양.**

릴리스 생성 조건: 대상 브랜치 green + version bump 명확 + changelog 준비 + artifact 빌드 가능 + 필요시 마이그레이션/롤백 노트. 자세한 정책은 `docs/RELEASING.md`.

## 완료의 정의

작업은 code change로 끝나지 않는다. **PR 가능성, CI 상태, release 영향, version bump, changelog, rollback/migration까지 판단해야 끝난다.**

<!-- @ai-ops-standards:end -->

## Project-specific

<!-- 이 아래는 프로젝트 고유 내용. 전파 스크립트가 건드리지 않습니다. -->
_(none yet)_
