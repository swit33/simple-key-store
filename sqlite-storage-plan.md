# План добавления сохранения и чтения из SQLite

> **Текущее состояние (2026-09-17, ветка `agent/full-handover`).** Это исторический документ, он не переписывается. Пункты 1, 2 и 4 раздела «Что сейчас стоит поправить» уже выполнены коммитом `322ac1f` и текущим `internal/store` (используется modernc, `Open(path)` обходится без `CheckDb/GenerateDb`, запись хранит только `ciphertext+nonce`). По пункту 3 `Open(path)` уже параметризован, но XDG-путь появится только в M1 (`internal/config`); текущая CLI пока вызывает `Open(".")`. В пункте 5 проброс exit-кода `Main` и пустой `sksd/main.go` исправлены в `875e2b1`, остальные заглушки заменит M1 по §6 спеки. Эта шапка уточняет состояние исторического чек-листа; остальные требования документа сохраняют силу вместе с `secrets-spec.md`.

## Что сейчас стоит поправить

1. **Драйвер не соответствует спеке**
   
   В `go.mod` добавлен `github.com/mattn/go-sqlite3`, а спека требует `modernc.org/sqlite`. `mattn` использует cgo и усложнит кросс-сборку.

2. **`CheckDb` и `GenerateDb` не нужны**
   
   `os.Stat` перед открытием БД создаёт race и скрывает ошибки доступа. SQLite сам создаёт файл. Нужно открыть БД и выполнить миграцию через `CREATE TABLE IF NOT EXISTS`.

3. **БД не должна быть `test.db` в текущем каталоге**
   
   Путь следует передавать в `store.Open(path)`. Для клиента это XDG-путь `~/.local/share/secrets/cache.db`.

4. **Нельзя сначала сохранять plaintext «временно»**
   
   По спецификации даже первая версия должна писать только `ciphertext + nonce`, включая WAL. Поток данных:

   `CLI → encrypt → store.Set(ciphertext, nonce)`

5. **В CLI сейчас есть ошибки**

   - `main()` игнорирует код возврата `Main`;
   - usage обещает `set <key> <value>`, но `cmdSet` принимает один аргумент;
   - по спецификации value нельзя передавать через argv;
   - `cmdGet` печатает `set called`;
   - пустой `internal/cli/sksd/main.go` ломает `go test ./...`.

## Минимальный дизайн store

Достаточно одного concrete type без интерфейсов и repository-абстракций:

- `store.Open(path) (*Store, error)`;
- `Store.Close() error`;
- `Store.Set(ctx, path, ciphertext, nonce) error`;
- `Store.Get(ctx, path) (ciphertext, nonce []byte, error)`.

### Что делает `Open`

1. Создаёт каталог с правами `0700`.
2. Открывает SQLite через `database/sql`.
3. Ограничивает число соединений до одного writer через `SetMaxOpenConns(1)` — для M1 этого достаточно.
4. Устанавливает PRAGMA из спеки:
   - `journal_mode=WAL`;
   - `busy_timeout=5000`;
   - `synchronous=NORMAL`;
   - `temp_store=MEMORY`.
5. Создаёт таблицы `local_secrets` и `local_meta`.

## Минимальная схема M1

В `local_secrets` для первого вертикального среза нужны:

- `path` — primary key;
- `ciphertext` — not null;
- `nonce` — not null;
- `deleted` — default 0.

Поля синка (`rev`, `version`, `base_version`, `dirty`, `conflict`) можно сразу взять из утверждённой схемы, но пока не реализовывать их поведение.

## Сохранение

Для `Set` использовать SQLite UPSERT:

- новая запись — insert;
- существующий path — обновить `ciphertext` и `nonce`, сбросить tombstone;
- запрос выполнять через `ExecContext`;
- если шифрование завершилось ошибкой, SQL вообще не должен выполняться.

## Чтение

Для `Get`:

- использовать `QueryRowContext` по `path` и `deleted = 0`;
- читать только `ciphertext` и `nonce`;
- `sql.ErrNoRows` преобразовать в отдельную ошибку store, например `ErrNotFound`;
- CLI преобразует `ErrNotFound` в exit code `2`;
- после расшифровки `get` пишет только значение в stdout, без диагностических строк.

## Связь с CLI

Один запуск команды:

1. Получить XDG-путь.
2. Открыть store.
3. Прочитать или создать `machine.key`.
4. Для `set`:
   - проверить один аргумент `path`;
   - прочитать value из stdin или hidden prompt;
   - зашифровать с AAD `local|secrets/<schema>|<path>`;
   - вызвать `Store.Set`.
5. Для `get`:
   - вызвать `Store.Get`;
   - расшифровать;
   - вывести значение без добавочного перевода строки.

## Порядок реализации

1. Заменить драйвер на `modernc.org/sqlite`.
2. Реализовать `Open`, `Close` и миграцию.
3. Добавить `Set/Get` для ciphertext.
4. Добавить AES-GCM и `machine.key`.
5. Подключить CLI.
6. Добавить два минимальных теста:
   - `set → get` возвращает исходное значение;
   - маркер plaintext отсутствует в `cache.db`, `-wal` и `-shm`.

## Что не нужно для M1

Не добавлять отдельные DAO, repository-интерфейсы, migration framework и transaction manager. Для M1 достаточно одного `Store`, встроенной SQL-миграции и `database/sql`.
