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
