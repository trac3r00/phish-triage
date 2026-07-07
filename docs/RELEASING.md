# Release & Merge Policy — phish-triage

이 문서는 언제 PR을 merge하고, 언제 릴리스를 자르고, hotfix가 어떻게 흐르는지 정의한다.
"CI green"은 필요조건이지 충분조건이 아니다.

## 필수 merge 게이트 (Required merge gates)

PR은 다음이 **모두** 성립할 때만 merge:

1. **최신 커밋에서 CI green** (이전 커밋 아님).
2. **PR 본문 완비** — 연결 이슈, Why 섹션, 검증 증거. Why 비면 CI 무관하게 merge 불가.
3. **검증 증거.** 가장 작은 관련 명령 출력 또는 CI 증거. UI/route 변경은 수동 검증도.
4. **PR 하나 = 논리적 변경 하나.** 기능+무관 리팩터 섞이면 쪼갠다.
5. **배치 soak 규칙** (배포 자동화 repo): 배포 유발 PR은 15분에 하나만. docs/CI-only는 자유.

## main 직접 push

허용 안 됨 (owner·자동화 포함). broken-main 긴급 상황만 예외 — 24h 내 회고 이슈.

## 릴리스 정책 (Release policy)

- **언제 tag:** 의미 있는 사용자 대면 마일스톤(새 기능, 큰 UX 변화, 보안 수정) 후, 또는 최대 ~2주 누적. 순수 의존성 churn은 릴리스 사유 아님.
- **버전 (SemVer):** breaking = major, 새 기능 = minor, 수정/deps = patch. **같은 주 minor 남발 = version inflation.**
- **changelog:** tag 전 갱신. 사용자 관점으로 — 버전/날짜 헤드라인, Features/Fixes/Dependencies/Docs 그룹.
- **release notes:** merge된 PR 제목 + changelog에서 생성. 각 줄에 PR 링크.
- **tags:** pre-tag 체크 통과한 정확한 SHA에 `vX.Y.Z`.
- **pre-tag 체크:** `pytest` — 정확한 tag SHA에서 로컬 또는 CI.

### 릴리스 vs 머지-only

- **릴리스 관리 repo** (tag/release 있음): merge 후 PR 쌓아서 릴리스로 끊는다. main 방류 ❌. → `release-train` 패턴.
- **릴리스 안 하는 repo** (tag 0): merge만.
- **핫픽스(보안/버그):** 즉시 merge, 필요시 patch 릴리스.

## Hotfix flow

1. `hotfix/<slug>` 브랜치 (main에서).
2. PR + 템플릿 (Why = 인시던트 설명 + 증거).
3. 단독 merge (배치 ❌), 배포 완료까지 확인.
4. 배포 실패 시 revert 먼저, 진단 나중.

## Rollback

- 우선: PR 통한 `git revert` (히스토리 보존, CI/배포 재실행).
- 앵커: 릴리스 tag = known-good. `gh release list`로 마지막 확인.
