# simple-key-store

Локальное зашифрованное хранилище секретов на Go.

Сейчас завершён **M1: полностью офлайн-клиент**. Команды `set`, `get`, `ls`, `rm` и `export` работают через локальный SQLite-кэш. Сервер, login, синхронизация и конфликты относятся к M2–M4 и пока не реализованы.

## Возможности M1

- значения шифруются AES-256-GCM до записи в SQLite;
- отдельный случайный nonce для каждой записи;
- шифртекст привязан к path через AAD;
- ключ машины хранится рядом с БД в `machine.key`;
- XDG-пути, права `0700` для каталога и `0600` для БД/ключа;
- точное сохранение произвольных байтов, включая переводы строк и NUL;
- tombstone-удаление через `rm`;
- экспорт в `dotenv`, `dotenv-export`, `shell` и JSON;
- безопасный POSIX quoting и отсутствие ANSI при pipe;
- основной gate проверяет race, lint, build и интеграционные сценарии;
- отдельный интеграционный тест доказывает отсутствие plaintext в файлах кэша.

## Требования

- [mise](https://mise.jdx.dev/);
- Linux или другая POSIX-система для shell-интеграционных тестов;
- версии Go и инструментов устанавливаются из `mise.toml`.

## Установка инструментов

```sh
mise install
mise run deps
mise run check
```

## Сборка

Статический бинарь без cgo:

```sh
mkdir -p bin
CGO_ENABLED=0 go build -o bin/secrets ./cmd/secrets
```

Для разработки без установки:

```sh
go run ./cmd/secrets --help
```

`cmd/secretsd` пока является заглушкой для будущего M2-сервера.

## Где хранятся данные

По умолчанию:

| Файл | Назначение | Права |
|---|---|---:|
| `~/.local/share/secrets/cache.db` | зашифрованный SQLite-кэш | `0600` |
| `~/.local/share/secrets/machine.key` | локальный 32-байтный AES-ключ | `0600` |
| `~/.config/secrets/config.toml` | будущая конфигурация сервера | ещё не создаётся в M1 |
| `~/.local/share/secrets/` | каталог данных | `0700` |

Поддерживаются `XDG_DATA_HOME` и `XDG_CONFIG_HOME`. Относительные XDG/HOME-пути отклоняются.

> `machine.key` и `cache.db` нужно рассматривать как одну пару. Потеря ключа делает кэш нерасшифровываемым.

## Path

Допустимый path:

```text
[a-z0-9._/-]{1,512}
```

Дополнительные правила:

- только lowercase;
- без ведущего и завершающего `/`;
- без пустых сегментов;
- сегменты `.` и `..` запрещены.

Примеры:

```text
deepseek/api_key
prod/pullmd/token
searxng/api_url
```

## Запись секрета

### Интерактивно

По умолчанию значение читается с терминала без эха:

```sh
secrets set deepseek/api_key
```

Явный вариант:

```sh
secrets set deepseek/api_key --prompt
```

### Из stdin

```sh
secrets set deepseek/api_key --stdin < secret.txt
```

Или из другой команды:

```sh
pass show services/deepseek | secrets set deepseek/api_key --stdin
```

Значение **нельзя** передавать позиционным аргументом: оно попало бы в history и список процессов.

Максимальный размер значения — **1 MiB**. Для крупных значений используйте `--stdin`: терминальный prompt предназначен для коротких значений.

## Чтение

```sh
secrets get deepseek/api_key
```

`get` печатает точные байты значения и не добавляет перевод строки. Для удобного просмотра текста:

```sh
secrets get deepseek/api_key
printf '\n'
```

`--raw` принимается как совместимый no-op: вывод M1 и так всегда raw.

## Список ключей

```sh
secrets ls
```

Результат — отсортированные live-path, по одному на строку. Значения не выводятся.

`--tree` и `--long` отложены до M4, где появится полноценный терминальный UI.

## Удаление

```sh
secrets rm deepseek/api_key
```

Запись не удаляется физически: создаётся tombstone. Это нужно будущей синхронизации.

## Экспорт

Формат по умолчанию — `dotenv-export`:

```sh
secrets export
```

Пример:

```sh
export DEEPSEEK_API_KEY='synthetic-value'
export SEARXNG_API_URL='https://example.invalid'
```

### Форматы

```sh
secrets export --format dotenv
secrets export --format dotenv-export
secrets export --format shell
secrets export --format json
```

- `dotenv`: `NAME='value'`;
- `dotenv-export`: `export NAME='value'`;
- `shell`: POSIX-safe export-строки;
- `json`: плоский объект `path → value`.

Shell-форматы отклоняют значения с NUL. JSON отклоняет невалидный UTF-8, чтобы не искажать данные молча.

### Преобразование path в имя переменной

1. path переводится в uppercase;
2. `/`, `.`, `-` заменяются на `_`;
3. результат обязан соответствовать `[A-Z_][A-Z0-9_]*`.

Примеры:

| Path | Имя |
|---|---|
| `deepseek/api_key` | `DEEPSEEK_API_KEY` |
| `searxng/api_url` | `SEARXNG_API_URL` |
| `prod.some-key` | `PROD_SOME_KEY` |

Если два path дают одно имя, export завершается с ошибкой и ничего не печатает в stdout.

Path, начинающийся с цифры, можно исправить префиксом:

```sh
secrets export --prefix SKS_
```

### Подключение к shell

Вариант из спеки:

```sh
eval "$(secrets export --format dotenv-export 2>/dev/null)"
```

Более явно обрабатывающий ошибку вариант:

```sh
if secrets_env=$(secrets export --format dotenv-export); then
	eval "$secrets_env"
fi
unset secrets_env
```

Перед использованием можно проверить результат:

```sh
secrets export --format dotenv-export | sh -n
```

## Коды возврата

| Код | Значение |
|---:|---|
| `0` | успех |
| `1` | ошибка аргументов, конфигурации, ключа, криптографии или IO |
| `2` | допустимый path отсутствует или уже удалён |
| `3` | зарезервирован для конфликтов M3 |

При ошибке `get`/`export` ничего не печатают в stdout. Диагностика идёт в stderr и не содержит значения секрета.

## `SECRETS_NOCACHE`

Спека предусматривает remote-only режим:

```sh
SECRETS_NOCACHE=1 secrets export
```

В M1 сети ещё нет, поэтому все команды, читающие или изменяющие локальные значения, отказывают закрыто с кодом `1`. Кэш и ключ не создаются и не изменяются. Полноценный remote-only режим появится вместе с M2.

## Потеря `machine.key`

Если `cache.db` существует, а `machine.key` отсутствует или повреждён:

- команды завершаются с ошибкой;
- stdout остаётся пустым;
- новый ключ автоматически не создаётся;
- существующий кэш не перезаписывается.

В M1 серверного восстановления ещё нет. Без резервной копии `machine.key` локальные значения восстановить невозможно. Команда `login --reset-key` появится в M2 и сможет заново получить значения с сервера.

Для резервной копии остановите процессы `secrets` и копируйте весь каталог данных целиком, включая `cache.db` и `machine.key`. Ключ рядом с БД защищает от бытового поиска plaintext, но не от атакующего, получившего оба файла.

## Модель безопасности

M1 защищает от:

- случайного `cat`/`rg` по домашнему каталогу;
- индексаторов;
- plaintext в SQLite/WAL/SHM;
- перестановки шифртекста между path.

M1 не защищает от:

- пользователя/root, который может прочитать и БД, и `machine.key`;
- чтения памяти процесса;
- чтения окружения экспортированного shell-процесса;
- потери обоих файлов вместе.

Криптографические детали:

- AES-256-GCM;
- случайный nonce 12 байт на запись;
- клиентский AAD: `local|secrets/v1|<path>`;
- серверный домен зарезервирован как `secrets/v1|<path>`.

## Проверка проекта

Единственный gate готовности:

```sh
mise run check
```

Он запускает:

- `gofmt` check;
- `go vet`;
- `golangci-lint`;
- `go test -race ./...`;
- статическую сборку с `CGO_ENABLED=0`;
- `scripts/no-plaintext-test.sh`;
- `scripts/m1-eval-test.sh`.

Дополнительно:

```sh
mise run static
mise run tidy
mise run test:cover
```

## Текущий scope

Готово: **M1 — офлайн-клиент**.

Не реализовано:

- `secretsd serve`;
- login/enroll и токены;
- pull/push/sync;
- HLC и конфликты;
- history/diff/resolve;
- status/doctor/backup;
- стилизованный UI;
- deployment-артефакты.

Полный контракт находится в [`secrets-spec.md`](secrets-spec.md), решения — в [`DECISIONS.md`](DECISIONS.md), история выполнения — в [`ATTEMPTS.md`](ATTEMPTS.md).
