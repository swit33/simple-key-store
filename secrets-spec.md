# secrets — спека собственного стора ключей (Go)

Статус: контракт, rev 3. Дата: 2026-09-14. Автор спеки: Hermes, исполнитель: пользователь (свой код).

**Rev 3 (сужение скоупа):** инструмент — личная утилита для одного пользователя и двух машин: «ключи не в гите дотфайлов, но описаны в дотфайлах; на второй машине `login` → sync → ключи на месте; анлок пассивный, не сильнее ключей в `.zshenv`». Из v1 убраны HLC, конфликтная машина (conflicts/resolve/diff/history), lipgloss-UI и exit-код 3: синк — LWW (последний push выигрывает, редкая одновременная правка двух машин решается повторным `set`). UI (M4) — отдельный скрипт на gum поверх CLI, в духе `pkgm`.

**Rev 2:** клиентский кэш шифруется ключом машины, который лежит рядом с БД. Модель угроз на клиенте: «защита от `rg OPENAI_API_KEY`», а не от реальной атаки. Серверный ключ (`vault.key`) и ключ машины — разные ключи, сервер ключ клиента не знает и не хранит.

## 0. Что делаем

Замена `~/.zshenv` с API-ключами на сервер + CLI.

- Один репо, два бинаря: `secretsd` (сервер, живёт на боксе, нативный systemd-юнит) и `secrets` (CLI на каждой машине).
- Хранение — SQLite. На сервере значения шифруются at-rest, на клиенте тоже: локальная БД шифруется ключом машины.
- Расшифровка на клиенте автоматическая, без мастер-паролей и unlock-промптов: ключ машины лежит файлом рядом с БД (пассивный анлок — принимаемая модель угроз, не слабее прежнего `.zshenv`).
- Синк: pull/push по rev-счётчику, семантика LWW (§4). Конфликтной машины нет: один пользователь, две машины, одновременная правка одного ключа — редкость, решается повторным `set`.
- Интерактивный UI — отдельный скрипт на gum (M4), не внутри Go-бинарника.

Не делаем: веб-дашборд, пользователи/роли/RBAC, шаринг-ссылки, динамические секреты, k8s-оператор, плагины, телеметрию, MCP-сервер (отдельным решением позже), мастер-пароль/unlock на клиенте, HLC/версионные строки, конфликты/resolve/diff/history, lipgloss-стилизацию внутри бинарника.

Референс по UX: `infisical export --format=dotenv-export` (строка для `.zshenv`), `rbw` (локальная копия), `~/dotfiles/.local/bin/pkgm` (gum-меню).

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
- Шифруется **всё, что содержит значение**: `local_secrets`, `outbox`, токен. В БД не должно быть ни одного plaintext-значения, включая `-wal`/`-shm`.
- `PRAGMA temp_store=MEMORY` — чтобы SQLite не сбрасывал временные страницы с расшифрованными данными на диск.
- В stderr/логи значения и токены не попадают никогда.
- Параноидальный режим: `SECRETS_NOCACHE=1` — значения локально не сохранять, всегда тянуть с сервера.

Что НЕ защищено и принимается как есть: значения видны в окружении процессов (`ps e`, `/proc/<pid>/environ`) на время жизни шелла; root на машине читает всё; память процесса не защищена.

## 2. Схема данных (сервер, SQLite)

`PRAGMA journal_mode=WAL`, `busy_timeout=5000`, `synchronous=NORMAL`, `temp_store=MEMORY`. Таблица `meta` хранит `schema_version`.

- `meta(key TEXT PRIMARY KEY, value TEXT)` — schema_version, server_id
- `secrets(path TEXT PRIMARY KEY, ciphertext BLOB, nonce BLOB, rev INTEGER, updated_at INTEGER, updated_by TEXT, deleted INTEGER DEFAULT 0)`
- `changes(seq INTEGER PRIMARY KEY AUTOINCREMENT, change_id TEXT UNIQUE, path TEXT, rev INTEGER, op TEXT, ts INTEGER, author_node TEXT)` — лог курсора синка (pull `since seq`); `change_id UNIQUE` — идемпотентность ретраев push (D15)
- `tokens(id TEXT PRIMARY KEY, label TEXT, hash BLOB, read_only INTEGER DEFAULT 0, key_fingerprint TEXT, created_at INTEGER, last_used_at INTEGER, revoked_at INTEGER)`

Историй версий (`secret_history`) и таблицы конфликтов (`conflicts`) в v1 нет: LWW-синк не порождает неразрешённых состояний, откат значения делается явным `set` старого значения (D25).

Соглашения:
- `path` = `[a-z0-9._/-]{1,512}`, lowercase, без ведущего слэша, `/` как разделитель (иерархия `prod/pullmd/token`).
- `rev` — единственный счётчик версий path, инкрементируется сервером при каждом применённом изменении.
- Удаление = tombstone (`deleted=1`), чтобы удаление доезжало до других машин. Tombstone чистится по возрасту отдельной админ-командой (v2).

## 3. Версии и порядок изменений (LWW)

HLC нет (D25). Единственная версия записи — серверный `rev`: сервер инкрементирует его при каждом применённом изменении path. Порядок изменений на всех машинах совпадает автоматически, потому что порядок один — порядок применения на сервере (`changes.seq`).

Правила push:
- Клиент отправляет `change_id` (uuid, генерируется один раз при офлайн-правке), `path`, `op`, `value` и `last_seen_rev` (последний `rev`, который клиент видел для этого path при pull).
- Если `last_seen_rev` равен текущему серверному `rev` (или записи ещё нет и `last_seen_rev` пуст) — применяется, `rev++`, запись в `changes`.
- Если `rev` сервера ушёл вперёд после последнего pull клиента — **LWW**: сервер применяет пришедшее значение, `rev++`, а клиент узнаёт об этом на следующем pull. Молчаливое затирание возможной офлайн-правки второй машины — принимаемая семантика (D25): риск ограничен одновременным edit/edit от одного человека на двух машинах; клиент хранит `last_seen_rev` и предупреждает в stderr, когда его push перезаписал более свежую версию.
- `change_id` уже применён → 200 без изменений (идемпотентность ретраев).

## 4. Синк-протокол

Курсор — ТОЛЬКО серверный `changes.seq` (никогда не время). Клиент хранит `last_seq`.

`GET /v1/sync?since=<seq>&limit=500`
```json
{"changes":[{"seq":42,"change_id":"uuid","path":"deepseek-api","rev":3,"op":"set","deleted":false,"value":"sk-...","author":"node-uuid"}],
 "cursor":42,"has_more":false}
```

`POST /v1/sync`
```json
{"node_id":"node-uuid","changes":[{"change_id":"uuid","path":"deepseek-api","op":"set","value":"sk-new","last_seen_rev":2}]}
```
Ответ: `{"applied":[{"path":..,"rev":..}],"cursor":N}`

Правила приёма на сервере (детерминированно):
1. `change_id` уже применён → 200 без изменений (идемпотентность ретраев).
2. `last_seen_rev` совпадает с текущим `rev` path (или пуст при отсутствии записи) → применить, `rev++`, записать в `changes`.
3. `last_seen_rev` отстаёт → всё равно применить (LWW, §3), `rev++`, записать в `changes`.
4. delete применяется так же, как set: tombstone, `rev++`. Delete поверх более свежего set не является конфликтом — tombstone доезжает, «потерянное» значение восстанавливается повторным `set`.

Порядок работы клиента: pull → merge в кэш → push outbox → короткий pull. Всё это одной командой `secrets sync`.

Значения по проводу идут расшифрованными (TLS + bearer-токен), на диск — только шифртекст.

Лимиты и защита: значение ≤ 1 MiB, path ≤ 512 байт, ≤ 500 изменений в батче, rate-limit на `/v1/auth/login` 5/мин на IP.

## 5. Клиентский кэш, ключ машины и очередь

Пути (XDG, не дотфайлы):
- `~/.local/share/secrets/cache.db` — зашифрованные значения, состояние, outbox
- `~/.local/share/secrets/machine.key` — 32 байта, 600, рядом с БД
- `~/.config/secrets/config.toml` — url сервера, node_id (не секреты)

Таблицы:
- `local_secrets(path PRIMARY KEY, ciphertext, nonce, rev, dirty, deleted)`
- `outbox(change_id PRIMARY KEY, path, op, ciphertext, nonce, last_seen_rev, created_at, tries)`
- `local_meta(key, value)` — `last_seq`, `token_enc`+`token_nonce` (токен шифруется ключом машины); url/node_id живут в `config.toml` (D14)

Правила:
- Ключ машины создаётся при `secrets login`, если файла нет. `--reset-key` — сгенерировать новый и заново забрать вольт (старый кэш нечитаем, не пытаться «спасать»).
- Права: `cache.db` 600, `machine.key` 600, каталог 700. Проверяется в `secrets doctor` (и на старте — предупреждение в stderr).
- Offline-first: `get/ls/export` работают от кэша без сети. Сеть нужна для `sync`, `--remote`, `token`.
- КРИТИЧНО для `eval $(...)`: если сервер недоступен и кэш пуст — команда обязана вернуть НЕПУСТОЙ exit-код и ничего не печатать в stdout. Частично напечатанный export = молча потерянные ключи в шелле.
- Значение с `\n` внутри сохраняется как есть; `get` не добавляет лишних переводов строки.

## 6. CLI: команды и контракт

Команды:
- `secrets login <url>` — enroll: спрашивает одноразовый токен/пароль, создаёт `machine.key` (если нет), сохраняет url + node_id, шифрует и кладёт серверный токен в кэш.
- `secrets sync [--quiet]` — pull+push, печатает сводку (сколько применилось, поверх чего перезаписало).
- `secrets get <path>` — из кэша; `--remote` — только с сервера; `--raw` — без стилей.
- `secrets set <path> [--stdin|--prompt]` — значение НИКОГДА не берём из argv (иначе утекает в `ps` и history). Дефолт: prompt без эха.
- `secrets ls [--tree] [--long]`
- `secrets rm <path>`, `secrets mv <old> <new>`
- `secrets export [--format dotenv|dotenv-export|json|shell] [--sync] [--prefix P]`
- `secrets status` — доступность сервера, лаг по seq, dirty-счётчик, время последнего синка
- `secrets token add|list|revoke` — админ, только через loopback
- `secrets doctor` — доступность сервера, версия схемы, права на `cache.db`/`machine.key`, отсутствие plaintext в кэше

Контракт вывода (критично из-за `eval`):
- Стили ТОЛЬКО когда stdout — TTY и нет `NO_COLOR`/`--plain`. Иначе голый текст. В M2–M3 стилей нет (gum-скрипт в M4) — правило сохраняется для будущего UI.
- `get`/`export` не печатают в stdout ничего, кроме значений/экспортов. Все сообщения — в stderr.
- Коды выхода: `0` ок, `1` ошибка (сеть/сервер/конфиг), `2` нет такого ключа. Exit 3 не используется (конфликтов в v1 нет).
- `dotenv-export` — POSIX-safe квотинг (`export KEY='...'` с экранированием `'`), проверяется `sh -n`.
- В stderr никогда не попадает значение секрета или токен.

Строка для `.zshenv` (итоговая):
```sh
eval "$(secrets export --format dotenv-export 2>/dev/null)"
```

## 7. UI: gum-скрипт (M4)

Внутри Go-бинарника стилизации нет: lipgloss/bubbles не берём (D24). Интерактивный UI — отдельный скрипт в духе `~/dotfiles/.local/bin/pkgm`: CLI-команды остаются машинными контрактами, а gum-обёртка поверх них (`gum filter`/`gum confirm`) даёт интерактивный выбор ключа, подтверждение `rm`, просмотр `status`. Скрипт живёт в дотфайлах, не в этом репо. Правило «no ANSI при pipe» относится к самому CLI и остаётся неизменным.

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
- Зависимости: `modernc.org/sqlite` v1.58.0 (pure Go, без cgo → статические бинари и кросс-сборка под macOS/Windows), `spf13/cobra` v1.10.2, `google/uuid` v1.6.0. cgo/SQLCipher не берём: `modernc` не умеет SQLCipher, а cgo ломает кросс-сборку. lipgloss не берём (D24, §7 — UI на gum). Шифрование — **уровня значений** (envelope), а не всей БД.
- Дерево:
```
cmd/secrets/main.go        # CLI
cmd/secretsd/main.go       # сервер
internal/store/            # sqlite + миграции + транзакции
internal/crypto/           # envelope AES-256-GCM, ключ из файла (сервер и клиент)
internal/sync/             # pull/push, merge, outbox
internal/api/              # общие DTO клиента и сервера
internal/ui/               # TTY-детект, Print-хелпер (без стилей)
internal/config/           # XDG-пути, конфиг, ключ машины
scripts/                   # интеграционные тесты синка
```
- Тесты: `go test ./... -race` (race обязателен для синка).

## 10. Деплой на боксе (по нашим правилам)

- `~/apps/secrets/` — бинарь `secretsd` + `data/secrets.db` + `data/vault.key` (600, homelab).
- Юнит `~/srv/secrets.service` + симлинк в `~/.config/systemd/user/`, `Restart=always`, `ExecStartPre=secretsd migrate`, хардненинг (`NoNewPrivileges`, `ProtectSystem=strict`, `ReadWritePaths=~/apps/secrets/data`, `PrivateTmp`).
- Caddy: `~/scripts/caddy-conf set secrets < файл` → домен в `~/caddy-sync/domains-extra` → `caddy-conf reload` (автоген domains → hosts-sync).
- Клиентские бинари: `go build ./cmd/secrets` → scp/`make install` на машины, либо Gitea-релизы.
- CI (Gitea Actions, act-runner host-режим): `go vet ./...`, `go test -race ./...`, сборка, атомарная выкладка бинаря + `systemctl --user restart secrets`.
- Бэкап: cron раз в сутки `secretsd backup` + ротация; раз в месяц — тест восстановления на копию.

## 11. Тест-план (что должно быть доказано)

- Идемпотентность: один `change_id` дважды → одна запись в `changes`.
- Порядок: несколько машин синкуются с одним сервером → у всех одинаковый итоговый набор значений (порядок — серверный `seq`).
- LWW: push с устаревшим `last_seen_rev` → применяется, `rev++`, предупреждение в stderr; pull доезжает на вторую машину.
- Офлайн: правка при остановленном сервере → outbox → `sync` после подъёма → применилось.
- Tombstone: `rm` на машине A → после sync на машине B значение отсутствует (tombstone доезжает).
- **Отсутствие plaintext в кэше**: записать значение-маркер через `secrets set`, затем `rg -a 'MARKER' ~/.local/share/secrets/` (включая `-wal`/`-shm`) → пусто. Отдельно проверить, что маркер не появился в outbox и логах.
- Восстановление ключа: удалить `machine.key` → `get` падает с понятной ошибкой и кодом != 0; `login --reset-key` поднимает кэш заново с сервера.
- Контракт CLI: `secrets export | sh -n` чисто; `eval "$(secrets export)"` в чистом `sh` даёт ожидаемые переменные; при pipe нет ANSI (`| grep -q $'\e'` пусто); отсутствующий ключ → exit 2; пустой кэш + недоступный сервер → stdout пуст и exit != 0.
- Восстановление бэкапа: `VACUUM INTO` + restore в копию → `secrets get`/`ls` работают.
- Команды для CI:
```sh
go vet ./... && go test -race ./...
./scripts/sync-test.sh           # сервер в фоне + два клиента в tmp-каталогах
./scripts/no-plaintext-test.sh   # grep-тест по каталогу кэша
```

## 12. Дорожная карта

- **M1 — замена `.zshenv` (без сети).** ✅ Завершён: store + envelope-крипта + `machine.key`, `set/get/ls/rm/export`, контракт «no ANSI при pipe».
- **M2 — сеть (LWW).** `secretsd serve`, токены, enroll (`login`), `sync` (pull+push, outbox, rev + `last_seen_rev`). Семантика — LWW по §3 с предупреждением в stderr при перезаписи. DoD: два клиента в tmp-каталогах синкуются через сервер; офлайн-правка доезжает; tombstone доезжает; plaintext-тест синка пуст.
- **M3 — эксплуатация сервера.** `secretsd backup` + restore-тест, `deploy/`-артефакты (systemd/Caddy, применение руками по D19).
- **M4 — эксплуатация клиента + UI.** `doctor`, `status`, `export --sync` для `.zshenv`, tombstone-чистка (админ-команда), gum-скрипт в дотфайлах (§7, D24).

## 13. Открытые решения (нужны от тебя до старта)

Решены в rev 3 сужением скоупа (D25): HLC и конфликтная машина убраны из v1; UI — gum-скрипт. Из открытых вопросов rev 2:
1. Ключ сервера at-rest: файл `vault.key` — решено (D1).
2. Иерархия путей — решено (D2, lowercase, `/`).
3. Токены: enroll — read/write, админ — loopback (D3).
4. Домен и порт — решено (D4).
5. Теги/поля — нет (D5).
6. `secrets run --` — нет (D6).
7. История с откатом — нет; в rev 3 история убрана целиком (D25, D7 устарел).

## 14. Anti-scope (не делаем)

Веб-дашборд, RBAC/роли, шаринг-ссылки, ротация-плейбуки, k8s-оператор, плагины, встроенный git-бэкенд, телеметрия, MCP-сервер (отдельным решением позже), мастер-пароль/unlock на клиенте, SQLCipher и любые cgo-зависимости, HLC/версионные строки, таблицы конфликтов/истории, `conflicts/resolve/diff/history`-команды, lipgloss/bubbles внутри бинарника, exit-код 3.
