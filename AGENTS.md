# AGENTS.md

Инструкция для агента, который продолжает разработку `simple-key-store`.

## 1. Текущее состояние

Завершён **M1: офлайн-клиент**.

Работают:

- XDG-пути и lifecycle `machine.key`;
- AES-256-GCM envelope encryption;
- SQLite-кэш;
- `secrets set/get/ls/rm/export`;
- CLI-контракт кодов возврата и потоков;
- no-plaintext и eval/export integration gates.

Не реализованы M2–M4: сервер, login/enroll, сеть/sync (LWW по rev), status/doctor/export --sync, deploy-артефакты/backup, gum-UI. HLC, конфликтная машина (conflicts/resolve/diff/history) и lipgloss убраны из скоупа решением D25/D24 (спека rev 3).

`cmd/secretsd` намеренно остаётся минимальным placeholder до M2. Не изображай готовый сервер и не добавляй заглушки, проходящие gate без поведения.

## 2. Источники правды

При конфликте используй такой порядок:

1. [`secrets-spec.md`](secrets-spec.md) — продуктовый контракт и threat model.
2. [`DECISIONS.md`](DECISIONS.md) — принятые уточнения D1–D25; более позднее решение может явно заменить раннее (D24/D25 сузили скоуп спеки rev 3).
3. Код и исполняемые тесты текущего HEAD.
4. [`agent-loop-guide.md`](agent-loop-guide.md) — процесс, gates и матрица требований.
5. [`sqlite-storage-plan.md`](sqlite-storage-plan.md) — исторический план SQLite; не считай его точнее реализованного контракта.
6. [`ATTEMPTS.md`](ATTEMPTS.md) — append-only журнал доказательств, а не спецификация.

Критические границы:

- `secrets-spec.md` §1 (threat model) не ослаблять;
- `secrets-spec.md` §14 (anti-scope) не обходить;
- M1-границы зафиксированы D22/D23;
- `loop/ROADMAP_DONE` означает M1–M4 целиком и не должен появляться после одного M1.

Если нужен новый архитектурный выбор, сначала добавь следующее решение `Dxx` в `DECISIONS.md`, затем зависимый код.

## 3. Карта репозитория

```text
.
├── cmd/
│   ├── secrets/         тонкий entrypoint клиента
│   └── secretsd/        зарезервированный entrypoint M2
├── internal/
│   ├── cli/             Cobra-команды, orchestration, export
│   ├── config/          XDG-пути и machine.key
│   ├── crypto/          AES-GCM envelope и AAD domains
│   ├── store/           SQLite schema, queries и path validation
│   └── ui/              единая запись stdout/stderr и ANSI policy
├── scripts/
│   ├── no-plaintext-test.sh
│   ├── m1-eval-test.sh
│   └── expected-vars.txt
├── loop/
│   ├── mission.md       контракт автономного loop
│   └── run.sh           fail-closed runner
├── secrets-spec.md      продуктовая спецификация
├── DECISIONS.md         архитектурные решения
├── ATTEMPTS.md          append-only evidence diary
├── agent-loop-guide.md  процесс разработки
├── sqlite-storage-plan.md
└── mise.toml            версии инструментов и gates
```

## 4. Зависимости пакетов

Основное направление зависимостей:

```text
cmd/secrets
    └── internal/cli
        ├── internal/config
        ├── internal/crypto
        ├── internal/store
        └── internal/ui
```

Назначение:

- `cmd/secrets`: только вызов `cli.Execute`; бизнес-логики здесь быть не должно.
- `internal/cli`: связывает filesystem, key lifecycle, crypto и store; здесь находится пользовательский контракт.
- `internal/config`: вычисляет пути, создаёт/читает ключ, обеспечивает права и atomic write.
- `internal/crypto`: чистая криптография без SQLite/CLI/filesystem policy.
- `internal/store`: SQLite и валидация path; не знает plaintext-смысл значения.
- `internal/ui`: единственная policy-точка для вывода и ANSI.

Не создавай интерфейсы, factories или новые слои для одной реализации. Сначала ищи существующий helper, затем stdlib, затем уже минимальный новый код.

## 5. Основные потоки данных

### 5.1 `set`

```text
CLI args
→ ValidatePath
→ прочитать value из stdin или no-echo prompt
→ проверить ≤ 1 MiB
→ ResolvePaths
→ открыть существующий cache или создать layout первого set
→ Load/Create machine.key по D11
→ crypto.Seal(LocalDomain, path, value)
→ store.Set(ciphertext, nonce, tombstone=false)
```

Инварианты:

- значение никогда не передаётся argv;
- существующий cache без ключа — hard error, ключ не регенерируется;
- только первый локальный `set` без cache может создать ключ;
- ошибка не должна оставить partial layout или вывести значение.

### 5.2 `get`

```text
ValidatePath
→ ResolvePaths без read-side creation
→ Load machine.key
→ store.Get live row
→ crypto.Open(LocalDomain, path, ciphertext, nonce)
→ точные bytes в stdout без newline
```

Missing/tombstone: exit `2`, пустой stdout.

### 5.3 `ls`

```text
ResolvePaths
→ открыть существующий cache
→ store.List live rows
→ отсортированные path, один на строку
```

M1 не поддерживает `--tree` и `--long`.

### 5.4 `rm`

```text
ValidatePath
→ Load key/cache
→ store.Delete
→ tombstone=true, ciphertext/nonce очищены
```

Физически строку не удалять: tombstone нужен M2 sync.

### 5.5 `export`

```text
прочитать и расшифровать все live rows
→ проверить все path/name/value
→ обнаружить collisions
→ полностью сформировать output в памяти
→ одной записью отправить в stdout
```

Export обязан быть all-or-nothing: никакого partial stdout при ошибке.

## 6. Storage contract

### 6.1 Пути и права

- data dir: `${XDG_DATA_HOME:-$HOME/.local/share}/secrets`, mode `0700`;
- config dir: `${XDG_CONFIG_HOME:-$HOME/.config}/secrets`;
- DB: `cache.db`, mode `0600`;
- key: `machine.key`, mode `0600`, ровно 32 байта.

Относительный `XDG_DATA_HOME`, `XDG_CONFIG_HOME` или `HOME` отклонять. Read-команды не создают каталог, DB или ключ.

### 6.2 SQLite schema M1

`local_meta`:

- `schema_version=1`.

`local_secrets` содержит ровно девять колонок:

- `path` — primary key;
- `ciphertext` — encrypted value;
- `nonce` — GCM nonce отдельно от ciphertext;
- `rev`;
- `version`;
- `base_version`;
- `dirty`;
- `deleted` — tombstone flag;
- `conflict`.

Поля sync (rev/dirty/deleted) пока остаются со значениями M1 по умолчанию. HLC-колонок в schema M1 нет и не будет: синк — LWW по серверному `rev` (D25).

Не клади plaintext value в schema, временные таблицы, debug columns, migration logs или error strings.

### 6.3 PRAGMA на каждом соединении

DSN должен обеспечивать:

- `journal_mode=WAL`;
- `busy_timeout(5000)`;
- `synchronous=NORMAL`;
- `temp_store=MEMORY`.

Проверка должна охватывать больше одного pooled connection. Не возвращай `temp_store` на disk: это нарушит no-plaintext invariant.

### 6.4 Path и value

Path:

```text
[a-z0-9._/-]{1,512}
```

Запрещены leading/trailing slash, empty segment, `.` и `..`.

Value: максимум `1 MiB`, bytes opaque. Нельзя делать trim, нормализацию Unicode, добавлять newline или принудительно превращать в UTF-8.

## 7. Crypto contract

Алгоритм: AES-256-GCM.

- key: ровно 32 байта;
- nonce: `gcm.NonceSize()` (сейчас 12 байт), новый криптографически случайный nonce для каждой записи;
- nonce хранится отдельно;
- authentication failure — hard error без partial plaintext.

AAD domains:

```text
ServerDomain: secrets/v1|<path>
LocalDomain:  local|secrets/v1|<path>
```

Всегда используй `Domain.aad`; не собирай AAD в caller. Локальный и серверный ciphertext должны быть несовместимы. Path обязан входить в оба домена, чтобы перестановка строк не расшифровывалась.

Не логируй key, nonce+ciphertext pair или plaintext. Для тестов используй только синтетические fixtures.

## 8. CLI contract

### 8.1 Exit codes

- `0`: успех;
- `1`: input/config/key/crypto/IO error;
- `2`: path валиден, но live value отсутствует.

### 8.2 Потоки

- stdout — только машинно используемый успешный результат;
- stderr — диагностика без plaintext;
- `get` пишет точные bytes без newline;
- ошибки `get`/`export` оставляют stdout пустым;
- при pipe и `NO_COLOR` ANSI отсутствует.

Все user-visible записи проводи через `internal/ui`, а не через случайные `fmt.Print*` в командах.

### 8.3 `SECRETS_NOCACHE`

По D23 в M1 любое непустое значение переменной приводит к fail-closed для локальных value operations до доступа к cache/key.

Help остаётся доступным. Не превращай M1 в молчаливый no-op и не создавай filesystem artifacts.

### 8.4 Export

Форматы:

- `dotenv`;
- `dotenv-export` (default);
- `shell`;
- `json`.

Env-name:

```text
uppercase(path), где '/', '.', '-' → '_'
```

После `--prefix` имя должно соответствовать `[A-Z_][A-Z0-9_]*`. Collision или invalid name — exit `1`, пустой stdout.

Shell-like форматы отклоняют NUL. JSON отклоняет invalid UTF-8. Это не ограничивает opaque storage/get; это ограничения конкретных текстовых представлений.

## 9. Команды разработки

Установить pinned tools:

```sh
mise install
mise run deps
```

Обязательный gate:

```sh
mise run check
```

Он включает:

```text
fmt:check
vet
lint
test:race
build (CGO_ENABLED=0)
test:integration
```

Дополнительные проверки перед завершением значимого изменения:

```sh
mise run static
mise run tidy
go test -race -count=1 ./...
go mod verify
git diff --check
git status --short --branch
```

Integration отдельно:

```sh
bash scripts/no-plaintext-test.sh
bash scripts/m1-eval-test.sh
```

Coverage:

```sh
mise run test:cover
```

`cover.out` — локальный generated artifact, не коммитить.

## 10. Что доказывают интеграционные тесты

### `scripts/no-plaintext-test.sh`

- собирает собственный static client в temp dir;
- изолирует `HOME` и XDG;
- пишет уникальный synthetic marker через stdin;
- проверяет byte-exact round trip;
- сканирует все файлы data dir, включая существующие WAL/SHM;
- падает при plaintext marker или нарушении stream/exit contract.

### `scripts/m1-eval-test.sh`

- использует только synthetic values;
- проверяет no ANSI;
- запускает `sh -n`;
- выполняет clean-shell eval и сравнивает exact bytes;
- сверяет env names с `scripts/expected-vars.txt`;
- проверяет missing-key и empty-export fail-closed.

Никогда не читай реальные значения из `~/.zshenv` для fixture. В `expected-vars.txt` допустимы только публичные имена переменных, не значения.

## 11. Правила изменения кода

Для любого нетривиального изменения:

1. Прочитай целиком затрагиваемые файлы и найди всех callers.
2. Сопоставь изменение с `secrets-spec.md` и `DECISIONS.md`.
3. Если решения нет — сначала запиши Dxx.
4. Добавь минимальный падающий тест.
5. Исправь root cause в общей точке, а не симптомы в callers.
6. Запусти targeted race test.
7. Запусти полный gate и static/tidy.
8. Для security/storage/CLI-контракта проверь killability теста в temp copy.
9. Обнови `ATTEMPTS.md` только добавлением новой записи.
10. Зафиксируй локальный commit; push/PR/deploy только по отдельному явному запросу.

Не ослабляй существующий тест ради зелёного gate. Изменение ожидаемого поведения требует предварительного решения и проверки threat model.

## 12. Test design

- Тесты обязаны использовать temp dirs и synthetic fixtures.
- Не трогай реальный HOME/XDG.
- Security tests должны проверять не только error, но и отсутствие partial output/artifacts.
- CLI tests проверяют exit code, stdout и stderr отдельно.
- Crypto tests должны доказывать honest round trip и failure на wrong key/path/domain/tamper.
- Store tests проверяют schema, PRAGMAs на pooled connections, permissions, concurrency и tombstones.
- Для нового branch/loop/parser/security path оставь один минимальный тест, который падает при удалении логики.
- Не добавляй sleep-based coordination, skips, `|| true`, fake gates или golden files без необходимости.

## 13. Scope M2–M4

Не реализуй будущий слой «на всякий случай».

### M2

Только при отдельном запросе:

- real `secretsd`;
- config.toml server identity;
- enroll/login/tokens;
- HTTP API за Caddy (TLS);
- pull/push/sync — LWW по серверному `rev` (D25);
- outbox и tombstone;
- machine-key reset с повторным pull.

### M3

- deploy-артефакты (`deploy/`, применение руками по D19);
- backup + restore-тест.

### M4

- `doctor`, `status`, `export --sync`;
- tombstone-чистка;
- gum-скрипт UI в дотфайлах (D24), не lipgloss в Go;
- observability и operator docs.

При переходе к следующему milestone сначала обнови решения и матрицу evidence. Не добавляй compatibility shim для ещё несуществующей функции.

## 14. Запреты

Без явного запроса пользователя нельзя:

- push;
- открывать PR;
- выполнять реальный deploy;
- читать/копировать реальные секреты;
- менять git hooks;
- создавать `loop/ROADMAP_DONE` до полного M1–M4;
- ослаблять permissions, AAD, no-plaintext или fail-closed поведение;
- добавлять TODO-заглушки, мёртвый код или speculative abstractions;
- заменять root-cause fix проверкой только в одном caller;
- коммитить generated artifacts (`cover.out`, temp DB, binaries).

Минимальный корректный diff предпочтительнее нового слоя. Удаление предпочтительнее дублирования. Но security validation, data-loss prevention и test evidence не упрощать.

## 15. Definition of Done для изменения

Изменение готово, когда:

- поведение соответствует спецификации и решениям;
- тест сначала мог поймать дефект и остаётся в gate;
- `mise run check`, `mise run static`, `mise run tidy` зелёные;
- uncached race tests зелёные для нетривиального изменения;
- integration/security smoke пройдены, если затронуты storage/crypto/export;
- `git diff --check` чист;
- docs/decision/attempt evidence обновлены при необходимости;
- рабочее дерево чистое после локального commit;
- независимый verifier не нашёл P0/P1 для milestone-level изменения.
