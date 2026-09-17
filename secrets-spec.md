# secrets — спека собственного стора ключей (Go)

Статус: контракт, rev 2. Дата: 2026-09-14. Автор спеки: Hermes, исполнитель: пользователь (свой код).

**Rev 2:** клиентский кэш теперь шифруется ключом машины, который лежит рядом с БД. Модель угроз на клиенте: «защита от `rg OPENAI_API_KEY`», а не от реальной атаки. Серверный ключ (`vault.key`) и ключ машины — разные ключи, сервер ключ клиента не знает и не хранит.

## 0. Что делаем

Замена `~/.zshenv` с API-ключами на сервер + CLI.

- Один репо, два бинаря: `secretsd` (сервер, живёт на боксе, нативный systemd-юнит) и `secrets` (CLI на каждой машине).
- Хранение — SQLite. На сервере значения шифруются at-rest, на клиенте тоже: локальная БД зашифрована ключом машины.
- Расшифровка на клиенте автоматическая, без мастер-паролей и unlock-промптов: ключ машины лежит файлом рядом с БД.
- Синк-движок с версиями и разрешением конфликтов диффом.

Не делаем: веб-дашборд, пользователи/роли/RBAC, шаринг-ссылки, динамические секреты, k8s-оператор, плагины, телеметрию, MCP-сервер (отдельным решением позже), мастер-пароль/unlock на клиенте.

Референсы по UX: `phase run` / `infisical export --format=dotenv-export` (строка для `.zshenv`), `rbw` (локальная копия), git (diff/история как концепция).

## 1. Модель угроз и крипта (решается первой)

**Сервер.** Сервер знает plaintext всех значений (иначе клиенту нужна клиентская крипта и unlock'и). Шифрование at-rest: AES-256-GCM по значению, ключ 32 байта в `data/vault.key` (600).
- Защищает: чтение БД из бэкапа/копии, случайный `cat secrets.db`, `rg` по домашнему каталогу.
- Не защищает: от root на боксе.

**Клиент.** Локальная БД (`cache.db`) тоже хранит только шифртекст значений. Ключ машины — `machine.key` (32 байта, 600) в том же каталоге.
- Заявленная модель угроз: **бытовой поиск, а не атака**. Ключ рядом с БД — значит любой, кто может прочитать БД, прочитает и ключ. Это защита от `rg OPENAI_API_KEY`, индексаторов (`mdfind`/`locate`/Spotlight), инструментов бэкапа и агентов, которые читают файлы, — а не от противника.
- Следствие, которое принимаем осознанно: потеря/кража каталога = утечка вместе с ключом. Если это когда-нибудь станет неприемлемо — только клиентская крипта с паролем, то есть возврат к тому, от чего мы ушли.
- Ключ машины генерируется при `secrets login` (до первого pull) и живёт в `~/.local/share/secrets/` — **не в дотфайлах** и не в git. Это принципиально: ключ не попадает в `.zshenv`.
- Серверный и клиентский ключи независимы. Серверный ключ не покидает бокс, ключ машины не покидает машину и серверу не отправляется.
- Токен сервера на клиенте тоже шифруется ключом машины и лежит внутри `cache.db` — на диске остаётся ровно два артефакта: зашифрованная БД и ключ рядом с ней.

Общие правила крипты:
- Nonce 12 байт `crypto/rand` на каждую запись, переиспользование запрещено (иначе GCM ломается).
- AAD = `"secrets/<schema>|" + path` — шифртекст нельзя переставить между ключами. На клиенте добавляется префикс `local|`, чтобы клиентский и серверный шифртекст были несовместимы.
- Шифруется **всё, что содержит значение**: `local_secrets`, `outbox`, история, staging-значения конфликтов, любые локальные логи. В БД не должно быть ни одного plaintext-значения, включая `-wal`/`-shm`.
- `PRAGMA temp_store=MEMORY` — чтобы SQLite не сбрасывал временные страницы с расшифрованными данными на диск.
- В stderr/логи значения и токены не попадают никогда.
- Параноидальный режим: `SECRETS_NOCACHE=1` — значения локально не сохранять, всегда тянуть с сервера.

Что НЕ защищено и принимается как есть: значения видны в окружении процессов (`ps e`, `/proc/<pid>/environ`) на время жизни шелла; root на машине читает всё; память процесса не защищена.

## 2. Схема данных (сервер, SQLite)

`PRAGMA journal_mode=WAL`, `busy_timeout=5000`, `synchronous=NORMAL`, `temp_store=MEMORY`. Таблица `meta` хранит `schema_version`.

- `meta(key TEXT PRIMARY KEY, value TEXT)` — schema_version, server_id (uuid), hlc_last_ms, hlc_counter
- `secrets(path TEXT PRIMARY KEY, ciphertext BLOB, nonce BLOB, rev INTEGER, version TEXT, base_note TEXT, updated_at INTEGER, updated_by TEXT, deleted INTEGER DEFAULT 0, conflict INTEGER DEFAULT 0)`
- `secret_history(seq INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT, ciphertext BLOB, nonce BLOB, rev INTEGER, version TEXT, ts INTEGER, author_node TEXT, op TEXT)` — `op ∈ set|delete|resolve`; питает `diff`/`history`/откат
- `changes(seq INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT, rev INTEGER, version TEXT, op TEXT, ts INTEGER, author_node TEXT)` — лог курсора синка (pull `since seq`)
- `conflicts(id TEXT PRIMARY KEY, path TEXT, base_version TEXT, mine_version TEXT, mine_ciphertext BLOB, mine_nonce BLOB, theirs_version TEXT, theirs_ciphertext BLOB, theirs_nonce BLOB, created_at INTEGER, resolved_at INTEGER, resolution TEXT)`
- `tokens(id TEXT PRIMARY KEY, label TEXT, hash BLOB, read_only INTEGER DEFAULT 0, key_fingerprint TEXT, created_at INTEGER, last_used_at INTEGER, revoked_at INTEGER)`
- `audit(seq INTEGER PRIMARY KEY AUTOINCREMENT, token_id TEXT, action TEXT, path TEXT, ts INTEGER, ip TEXT, result TEXT)`

Соглашения:
- `path` = `[a-z0-9._/-]{1,512}`, lowercase, без ведущего слэша, `/` как разделитель (иерархия `prod/pullmd/token`).
- `rev` — счётчик версий конкретного path; `version` — строка HLC (см. §3).
- Удаление = tombstone (`deleted=1`), чтобы удаление доезжало до других машин. Физическая чистка истории — отдельная админ-команда (v2).

## 3. Версии и часы (HLC)

`version = "<unix_millis>:<counter>:<node_id>"`.

Правила:
- Перед записью: `ms = max(now_ms, hlc_last_ms)`; если `ms == hlc_last_ms` → `counter++`, иначе `counter = 0`; сохранить `hlc_last_ms/ms`.
- При получении любого входящего сообщения подтягивать `hlc_last_ms` вверх.
- Сравнение версий: `ms` → `counter` → `node_id` (по строкам, детерминированно на всех репликах).

Зачем: монотонность при переводе часов назад, полный порядок, человекочитаемое время для UI. `time.Now()` для упорядочивания не использовать никогда — только HLC.

## 4. Синк-протокол

Курсор — ТОЛЬКО серверный `changes.seq` (никогда не время). Клиент хранит `last_seq`.

`GET /v1/sync?since=<seq>&limit=500`
```json
{"changes":[{"seq":42,"path":"deepseek-api","rev":3,"version":"1757850000123:0:abc","op":"set","deleted":false,"value":"sk-...","author":"node-uuid"}],
 "cursor":42,"has_more":false}
```

`POST /v1/sync`
```json
{"node_id":"node-uuid","changes":[{"change_id":"uuid","path":"deepseek-api","op":"set","value":"sk-new","base_version":"1757849999000:0:abc","version":"1757850000123:0:def"}]}
```
Ответ: `{"applied":[{"path":..,"rev":..,"version":..}],"conflicts":[{"path":..,"reason":"edit_edit","server_value":"..","server_version":".."}],"cursor":N}`

Правила приёма на сервере (детерминированно):
1. `change_id` уже применён → 200 без изменений (идемпотентность ретраев).
2. `base_version` совпадает с текущей версией → fast-forward: применить, `rev++`, записать в `changes` + `secret_history`.
3. Пустой `base_version` и записи нет → создание.
4. `base_version` не совпадает, `version` проигрывает текущей → конфликт: НЕ применять, записать в `conflicts` (оба значения), пометить path `conflict=1`, вернуть клиенту оба значения.
5. delete против edit → всегда конфликт (данные не теряем молча), дефолт-предложение — «оставить правку».
6. `version` новее, но `base_version` не совпадает → тоже конфликт (не LWW!). Молчаливая перезапись секрета — худшее, что тут может быть.

Порядок работы клиента: pull → merge в кэш → push outbox → короткий pull (получить применённое и конфликты). Всё это одной командой `secrets sync`.

Значения по проводу идут расшифрованными (TLS + bearer-токен), на диск — только шифртекст.

Лимиты и защита: значение ≤ 1 MiB, path ≤ 512 байт, ≤ 500 изменений в батче, rate-limit на `/v1/auth/login` 5/мин на IP.

## 5. Клиентский кэш, ключ машины и очередь

Пути (XDG, не дотфайлы):
- `~/.local/share/secrets/cache.db` — зашифрованные значения, состояние, outbox
- `~/.local/share/secrets/machine.key` — 32 байта, 600, рядом с БД
- `~/.config/secrets/config.toml` — url сервера, node_id (не секреты)

Таблицы:
- `local_secrets(path PRIMARY KEY, ciphertext, nonce, rev, version, base_version, dirty, deleted, conflict)`
- `outbox(change_id PRIMARY KEY, path, op, ciphertext, nonce, base_version, version, created_at, tries)`
- `local_meta(key, value)` — url, node_id, last_seq, hlc_last_ms/counter, `token_enc`+`token_nonce` (токен шифруется ключом машины)

Правила:
- Ключ машины создаётся при `secrets login`, если файла нет. `--reset-key` — сгенерировать новый и заново забрать вольт (старый кэш нечитаем, не пытаться «спасать»).
- Права: `cache.db` 600, `machine.key` 600, каталог 700. Проверяется в `secrets doctor` (и на старте — предупреждение в stderr).
- Offline-first: `get/ls/export` работают от кэша без сети. Сеть нужна для `sync`, `--remote`, `token`.
- КРИТИЧНО для `eval $(...)`: если сервер недоступен и кэш пуст — команда обязана вернуть НЕПУСТОЙ exit-код и ничего не печатать в stdout. Частично напечатанный export = молча потерянные ключи в шелле.
- Конфликты `export` не блокируют по умолчанию: экспортируем локальное значение, предупреждение в stderr. `--strict` — отказ с exit 3.
- Значение с `\n` внутри сохраняется как есть; `get` не добавляет лишних переводов строки.

## 6. CLI: команды и контракт

Команды:
- `secrets login <url>` — enroll: спрашивает одноразовый токен/пароль, создаёт `machine.key` (если нет), сохраняет url + node_id, шифрует и кладёт серверный токен в кэш.
- `secrets sync [--quiet]` — pull+push, печатает сводку и конфликты.
- `secrets get <path>` — из кэша; `--remote` — только с сервера; `--raw` — без стилей.
- `secrets set <path> [--stdin|--prompt]` — значение НИКОГДА не берём из argv (иначе утекает в `ps` и history). Дефолт: prompt без эха.
- `secrets ls [--tree] [--long]`
- `secrets rm <path>`, `secrets mv <old> <new>`
- `secrets history <path>`, `secrets diff <path> [--rev N]` — дифф версий (цветной только в TTY)
- `secrets conflicts`, `secrets resolve <path> --keep mine|theirs|both` (`both` → вторая запись `<path>.<node_id>`, ничего не теряем)
- `secrets export [--format dotenv|dotenv-export|json|shell] [--sync] [--prefix P]`
- `secrets status` — доступность сервера, лаг по seq, dirty-счётчик, конфликты, время последнего синка
- `secrets token add|list|revoke` — админ, только через loopback
- `secrets doctor` — TTY/ANSI, доступность сервера, дрейф часов, версия схемы, права на `cache.db`/`machine.key`, наличие конфликтов, отсутствие plaintext в кэше

Контракт вывода (критично из-за `eval`):
- Стили ТОЛЬКО когда stdout — TTY и нет `NO_COLOR`/`--plain`. Иначе голый текст.
- `get`/`export` не печатают в stdout ничего, кроме значений/экспортов. Все сообщения — в stderr.
- Коды выхода: `0` ок, `1` ошибка (сеть/сервер/конфиг), `2` нет такого ключа, `3` нерешённые конфликты (`--strict`).
- `dotenv-export` — POSIX-safe квотинг (`export KEY='...'` с экранированием `'`), проверяется `sh -n`.
- В stderr никогда не попадает значение секрета или токен.

Строка для `.zshenv` (итоговая):
```sh
eval "$(secrets export --format dotenv-export 2>/dev/null)"
```

## 7. Стилизация (lipgloss)

- lipgloss **v2.0.6**, модуль `github.com/charmbracelet/lipgloss/v2` — API v2, примеры под v1 не подходят.
- Стилизуем только `ls`, `status`, `conflicts`, `diff`, `doctor`, спиннер синка (bubbles/spinner) — и только в TTY.
- Цвета — из профиля терминала (colorprofile/termenv), RGB не хардкодим.
- Один хелпер вывода `ui.Print(out io.Writer, styled, plain string)`, чтобы «no ANSI при pipe» нельзя было забыть в отдельной команде.

## 8. Сервер `secretsd`

Подкоманды: `serve`, `migrate`, `token add|list|revoke`, `backup`, `doctor`, `version`.

- HTTP на `127.0.0.1:8686` (порт свободен). Домен `secrets.alexey-homelab.duckdns.org` добавляется Caddy после enroll.
- Эндпоинты: `GET /healthz`, `GET/POST /v1/sync`, `GET /v1/kv/<path>` (для curl), `GET /v1/status`, `POST /v1/auth/login`, `GET/POST/DELETE /v1/tokens`.
- Всё кроме `/healthz` требует `Authorization: Bearer <token>`; сравнение — `subtle.ConstantTimeCompare`, в БД только sha256 токена.
- Bootstrap (наш питфолл «первый=админ»): при старте без валидных токенов сервер печатает одноразовый enroll-токен в stdout, слушает loopback, домен в Caddy добавляется ПОСЛЕ enroll. Флаг `--require-enroll-token`.
- Запись в SQLite — один writer (мьютекс или канал в одну горутину); транзакции `BEGIN IMMEDIATE` (иначе `SQLITE_BUSY` под параллельными запросами).
- Логи: JSON-lines в stdout (journal), без значений и токенов.
- `secretsd backup` — `VACUUM INTO ~/backups/secrets/secrets-<date>.db` (консистентный снапшот без остановки сервера).

## 9. Структура репо и стек

- Go 1.27.1 (на боксе есть: `~/apps/go/go/bin/go`, в PATH через `~/apps/go/bin`).
- Зависимости: `modernc.org/sqlite` v1.58.0 (pure Go, без cgo → статические бинари и кросс-сборка под macOS/Windows), `spf13/cobra` v1.10.2, `charmbracelet/lipgloss/v2` v2.0.6, `google/uuid` v1.6.0, опционально `bubbles`. cgo/SQLCipher не берём: `modernc` не умеет SQLCipher, а cgo ломает кросс-сборку. Поэтому шифрование — **уровня значений** (envelope), а не всей БД.
- Дерево:
```
cmd/secrets/main.go        # CLI
cmd/secretsd/main.go       # сервер
internal/store/            # sqlite + миграции + транзакции
internal/crypto/           # envelope AES-256-GCM, ключ из файла (сервер и клиент)
internal/hlc/              # часы версий
internal/sync/             # pull/push, merge, конфликты
internal/api/              # общие DTO клиента и сервера
internal/ui/               # lipgloss, TTY-детект, Print-хелпер
internal/config/           # XDG-пути, конфиг, ключ машины
scripts/                   # интеграционные тесты синка
```
- Тесты: `go test ./... -race` (race обязателен для синка), HLC — на подменяемых часах (интерфейс `clock`, не `time.Now()` напрямую).

## 10. Деплой на боксе (по нашим правилам)

- `~/apps/secrets/` — бинарь `secretsd` + `data/secrets.db` + `data/vault.key` (600, homelab).
- Юнит `~/srv/secrets.service` + симлинк в `~/.config/systemd/user/`, `Restart=always`, `ExecStartPre=secretsd migrate`, хардненинг (`NoNewPrivileges`, `ProtectSystem=strict`, `ReadWritePaths=~/apps/secrets/data`, `PrivateTmp`).
- Caddy: `~/scripts/caddy-conf set secrets < файл` → домен в `~/caddy-sync/domains-extra` → `caddy-conf reload` (автоген domains → hosts-sync).
- Клиентские бинари: `go build ./cmd/secrets` → scp/`make install` на машины, либо Gitea-релизы.
- CI (Gitea Actions, act-runner host-режим): `go vet ./...`, `go test -race ./...`, сборка, атомарная выкладка бинаря + `systemctl --user restart secrets`.
- Бэкап: cron раз в сутки `secretsd backup` + ротация; раз в месяц — тест восстановления на копию.

## 11. Тест-план (что должно быть доказано)

- Конфликты: edit/edit → ровно один конфликт, оба значения живы; edit/delete → конфликт; create/create с разными значениями → конфликт; `resolve both` → две записи, ничего не потеряно.
- Идемпотентность: один `change_id` дважды → одна запись в `secret_history`.
- Порядок: два клиента с разным дрейфом часов (fake clock) → одинаковый порядок версий на обоих.
- Офлайн: правка при остановленном сервере → outbox → `sync` после подъёма → применилось, конфликтов нет.
- **Отсутствие plaintext в кэше**: записать значение-маркер через `secrets set`, затем `rg -a 'MARKER' ~/.local/share/secrets/` (включая `-wal`/`-shm`) → пусто. Отдельно проверить, что маркер не появился в истории, outbox и логах.
- Восстановление ключа: удалить `machine.key` → `get` падает с понятной ошибкой и кодом != 0; `login --reset-key` поднимает кэш заново с сервера.
- Контракт CLI: `secrets export | sh -n` чисто; `eval "$(secrets export)"` в чистом `sh` даёт ожидаемые переменные; при pipe нет ANSI (`| grep -q $'\e'` пусто); отсутствующий ключ → exit 2; пустой кэш + недоступный сервер → stdout пуст и exit != 0.
- Восстановление бэкапа: `VACUUM INTO` + restore в копию → `secrets get`/`ls` работают.
- Команды для CI:
```sh
go vet ./... && go test -race ./...
./scripts/sync-conflict-test.sh   # сервер в фоне + два клиента в tmp-каталогах
./scripts/no-plaintext-test.sh    # grep-тест по каталогу кэша
```

## 12. Дорожная карта

- **M1 — замена `.zshenv` (без сети).** store + envelope-крипта + `machine.key` + migrate, `set/get/ls/rm/export`, контракт «no ANSI при pipe». DoD: `eval "$(secrets export)"` даёт тот же набор переменных, что текущий `.zshenv`; `export | sh -n` чист; grep-тест по кэшу пуст.
- **M2 — сеть без конфликтов.** `secretsd serve`, токены, enroll (`login`), `sync` (pull+push). Временно LWW с громким предупреждением и `--force` — промежуточный режим, в повседневное использование не выводить.
- **M3 — конфликты.** HLC, `rev`/`base_version`, `conflicts/resolve/diff/history`, интеграционный тест на двух клиентов.
- **M4 — эксплуатация.** lipgloss-UI (`ls/status/conflicts`), `doctor`, backup + restore-тест, systemd/Caddy/CI, `export --sync` для `.zshenv`.

## 13. Открытые решения (нужны от тебя до старта)

1. Ключ сервера at-rest: файл `vault.key` (просто) или passphrase при старте (unseal-боль)? Предлагаю файл.
2. Иерархия путей (`prod/pullmd/token`) или только плоские имена?
3. Токены: все read/write, или для машин по умолчанию read-only?
4. Домен `secrets.alexey-homelab.duckdns.org` и порт `8686` — ок?
5. Нужны ли теги/поля (`--field`) кроме path→value?
6. Нужен ли `secrets run -- <cmd>` (инжект в env команды) в v1, или хватит `eval $(...)`?
7. Нужна ли история с откатом (`secrets rollback <path> --rev N`) в v1?

Решено (rev 2): клиентский кэш зашифрован ключом машины, ключ лежит рядом с БД; модель угроз — защита от бытового grep, не от атаки.

## 14. Anti-scope (не делаем)

Веб-дашборд, RBAC/роли, шаринг-ссылки, ротация-плейбуки, k8s-оператор, плагины, встроенный git-бэкенд, телеметрия, MCP-сервер (отдельным решением позже), мастер-пароль/unlock на клиенте, SQLCipher и любые cgo-зависимости.
