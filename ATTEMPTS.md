# ATTEMPTS — дневник лупа (append-only)

Дописывается только в конец. Задним числом не переписывается: иначе это отчёт о достижениях, а не дневник (гайд §7.2).
Формат записи об итерации — заголовок `## iteration N`, отдельная строка `- gate: green|red` и обязательная строка `- Не трогал:` (гайд §7.2).

---

## preflight — gate: green

- Коммит: `875e2b1` («preflight: establish green project gate»), ветка `agent/full-handover`, рабочее дерево чистое на старте хардoverа.
- Зафиксированы решения, от которых зависит код: `DECISIONS.md` D1–D20 (см. файл). Кода по M1–M4 в этой итерации не написано.
- Baseline (что было сломано до предполёта и закрыто в `875e2b1`):
  - `internal/cli/sksd/main.go` был 0 байт → сборка/`go test ./...` падали; добавлен `package main` + пустой `main`.
  - `go.mod` и `mise.toml`: Go 1.26.5 против Go 1.27 в спеке §9; выровнены на 1.27.1. `modernc.org/sqlite` числился indirect и сделан прямой зависимостью.
  - `internal/cli/sks/main.go`: `main()` игнорировал код возврата `Main`; exit-код проброшен. Заглушка `cmdGet` (`set called`) осознанно оставлена до переписывания CLI в M1.
  - `secrets-spec.md`: статус «черновик к реализации» → «контракт, rev 2» (гайд §1.1).
  - добавлены `.gitignore`, `.golangci.yml`, таск-набор и пины в `mise.toml`, тест `internal/store/store_test.go`.
- Гейт: `mise run check` → **green** (`fmt:check`, `vet`, `lint`, `test:race`, `build`), exit 0, воспроизведено на `875e2b1` в этой сессии. `test:integration` в `check` пока не входит — скриптов `scripts/*.sh` ещё нет (D9).
- Verifier: PASS (fresh `golang-pro`, run `e9d72d20-daef-4f77-be3f-a03b694816ff`): повторно зелёные `mise run check`, `mise run static`, tidy/hash stability и `go mod verify`; killability подтверждена дефектами для store, fmt, lint и tidy.
- Не трогал: M1–M4 (продуктовый CLI, config/crypto, сервер/sync/conflicts, UI/doctor/backup/deploy-артефакты). Всё изменённое перечислено выше; `scripts/` не создан.

## iteration 1 — M1

- gate: green (`mise run check`, включая `test:integration`, exit 0 на `674fa10`).
- Коммиты M1: `608914c` (XDG + machine.key), `d8733bc` (AES-256-GCM envelope), `a79b91f` (SQLite cache), `7cdcda6` (offline CLI/UI), `674fa10` (integration gate); решения D21–D23 записаны до зависимого кода.
- Закрыт офлайн-срез: `set/get/ls/rm/export`, точные raw-байты, лимит 1 MiB, path-валидация, exit 0/1/2, pipe без ANSI, fail-closed `SECRETS_NOCACHE`, POSIX-safe dotenv/shell и lossless JSON-only-for-UTF-8.
- Диск: каталог 0700, `machine.key`/`cache.db` 0600, значения только AES-256-GCM ciphertext+nonce с AAD `local|secrets/v1|<path>`, `temp_store=MEMORY` на соединениях.
- Интеграция: `scripts/no-plaintext-test.sh` — marker absent во всех файлах data dir; `scripts/m1-eval-test.sh` — `sh -n`, clean-shell eval, имена `DEEPSEEK_API_KEY`/`SEARXNG_API_URL`, missing-path и empty-export fail closed.
- Verifier: config/store/crypto/CLI проходили свежие read-only `golang-pro` проверки; финальный M1-аудит запускается на зафиксированном HEAD после этой записи.
- По явному изменению цели пользователя останавливаемся на полном M1. `loop/ROADMAP_DONE` не создаётся: он означает M1–M4 целиком.
- Не трогал: M2 (сервер, enroll/tokens, сеть/sync), M3 (HLC/conflicts/history/diff/resolve), M4 (styled UI/doctor/backup/deploy-артефакты).

## iteration 1 — final M1 audit

- Final verifier: PASS on `a125179` (fresh `golang-pro`, runs `83b3c0d3-fe05-4042-a470-3dfbaf90f980` and focused `7bc76bfb-1f8f-4493-8cda-bc870808774d`), no P0/P1.
- Fresh evidence: `mise run check`, `mise run static`, `mise run tidy`, uncached `go test -race -count=1 ./...`, `go mod verify`, both integration scripts and static-binary isolated smoke are green; worktree clean.
- Killability sample confirmed for store Set/Get, nonce/AAD, LocalDomain wrong-path binding, exit-code mapping, NUL export fail-closed, NOCACHE, permissions/PRAGMAs, plaintext scan and M1 env-name mapping.
- M1 complete. Per the user's narrowed goal, stop here; M2–M4 remain intentionally untouched and `loop/ROADMAP_DONE` remains absent.
