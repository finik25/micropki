
# MicroPKI

Учебный проект по созданию минимальной, но полной инфраструктуры публичных ключей (PKI).  
Реализован на Python с использованием библиотеки `cryptography`.

## Возможности

- Создание корневого (Root) и промежуточного (Intermediate) удостоверяющих центров
- Выпуск сертификатов по шаблонам: `server`, `client`, `code_signing`
- Поддержка Subject Alternative Names (SAN): dns, ip, email, uri
- Проверка цепочки сертификатов
- Шифрование приватных ключей CA (PKCS#8, AES-256)
- Поддержка внешних CSR (опционально)
- Логирование операций

## Структура проекта

```
micropki/
├── micropki/              # Основной пакет
│   ├── __init__.py
│   ├── __main__.py        # Точка входа для python -m micropki
│   ├── cli.py             # Парсер аргументов командной строки
│   ├── ca.py              # Логика CA (инициализация, выпуск, цепочки)
│   ├── certificates.py    # Создание X.509 сертификатов, CSR, шаблоны, SAN
│   ├── crypto_utils.py    # Генерация и шифрование ключей
│   └── logger.py          # Настройка логирования
├── tests/                 # Модульные тесты (pytest)
│   ├── test_ca.py
│   ├── test_certificates.py
│   ├── test_crypto_utils.py
│   └── test_sprint2.py
├── requirements.txt       # Зависимости (cryptography, pytest)
├── setup.py               # Установка пакета (entry point micropki)
├── .gitignore
└── README.md
```

## Требования

- Python 3.8 или выше
- Библиотека `cryptography` (устанавливается автоматически)

## Установка

1. Клонируйте репозиторий:
   ```bash
   git clone <url>
   cd micropki
   ```

2. Создайте виртуальное окружение:
   ```bash
   python -m venv .venv
   .venv\Scripts\activate      # Windows
   # source .venv/bin/activate   # Linux/macOS
   ```

3. Установите пакет в режиме разработки:
   ```bash
   pip install -e .
   ```

## Использование

### 1. Инициализация корневого CA (Root)

Создайте файл с парольной фразой (например, `pass.txt`):
```bash
echo "mysecret" > pass.txt
```

Выполните команду:
```bash
micropki ca init `
    --subject "/CN=My Root CA" `
    --key-type rsa `
    --key-size 4096 `
    --passphrase-file pass.txt `
    --out-dir ./pki `
    --validity-days 3650
```

После успешного выполнения в директории `pki` появятся:
- `private/ca.key.pem` – зашифрованный приватный ключ (PEM, PKCS#8)
- `certs/ca.cert.pem` – самоподписанный сертификат (PEM)
- `policy.txt` – текстовый документ политики CA

Проверка с помощью OpenSSL:
```bash
openssl x509 -in pki/certs/ca.cert.pem -text -noout
openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/ca.cert.pem
```

### 2. Создание промежуточного CA (Intermediate)

Создайте файл пароля для промежуточного CA:
```bash
echo "intsecret" > int_pass.txt
```

Затем выполните:
```bash
micropki ca issue-intermediate `
    --root-cert ./pki/certs/ca.cert.pem `
    --root-key ./pki/private/ca.key.pem `
    --root-pass-file pass.txt `
    --subject "CN=MicroPKI Intermediate CA" `
    --key-type rsa `
    --key-size 4096 `
    --passphrase-file int_pass.txt `
    --out-dir ./pki `
    --validity-days 1825 `
    --pathlen 0
```

Будут созданы:
- `pki/private/intermediate.key.pem` (зашифрован)
- `pki/certs/intermediate.cert.pem`

### 3. Выпуск сертификатов (end-entity)

#### Сертификат сервера (с DNS и IP SAN)
```bash
micropki ca issue-cert `
    --ca-cert ./pki/certs/intermediate.cert.pem `
    --ca-key ./pki/private/intermediate.key.pem `
    --ca-pass-file int_pass.txt `
    --template server `
    --subject "CN=example.com" `
    --san dns:example.com `
    --san dns:www.example.com `
    --san ip:192.168.1.10 `
    --out-dir ./certs `
    --validity-days 365
```
Результат: `certs/example.com.cert.pem` и `certs/example.com.key.pem` (незашифрованный).

#### Клиентский сертификат
```bash
micropki ca issue-cert `
    --ca-cert ./pki/certs/intermediate.cert.pem `
    --ca-key ./pki/private/intermediate.key.pem `
    --ca-pass-file int_pass.txt `
    --template client `
    --subject "CN=Alice Smith,EMAIL=alice@example.com" `
    --san email:alice@example.com `
    --out-dir ./certs
```

#### Сертификат для подписи кода
```bash
micropki ca issue-cert `
    --ca-cert ./pki/certs/intermediate.cert.pem `
    --ca-key ./pki/private/intermediate.key.pem `
    --ca-pass-file int_pass.txt `
    --template code_signing `
    --subject "CN=MicroPKI Code Signer" `
    --out-dir ./certs
```

### 4. Проверка цепочки сертификатов

```bash
micropki ca verify-chain `
    --leaf ./certs/example.com.cert.pem `
    --intermediate ./pki/certs/intermediate.cert.pem `
    --root ./pki/certs/ca.cert.pem
```

### 5. Проверка с помощью OpenSSL

```bash
# Просмотр информации о сертификате
openssl x509 -in ./certs/example.com.cert.pem -text -noout

# Проверка цепочки (root + intermediate)
openssl verify -CAfile ./pki/certs/ca.cert.pem -untrusted ./pki/certs/intermediate.cert.pem ./certs/example.com.cert.pem
```

## Поддержка внешнего CSR (опционально)

Вы можете предоставить готовый CSR вместо генерации ключа:
```bash
micropki ca issue-cert `
    --ca-cert ./pki/certs/intermediate.cert.pem `
    --ca-key ./pki/private/intermediate.key.pem `
    --ca-pass-file int_pass.txt `
    --template server `
    --csr ./path/to/request.csr `
    --san dns:example.com `
    --out-dir ./certs
```
В этом случае приватный ключ не сохраняется, используется открытый ключ из CSR.



## Управление базой данных сертификатов

### Инициализация базы данных

Перед выпуском сертификатов необходимо инициализировать SQLite базу данных. База будет хранить информацию о всех выданных сертификатах.

```bash
micropki db init --out-dir ./pki
```

### Просмотр выпущенных сертификатов

После того как вы выпустили несколько сертификатов (корневой, промежуточный, конечные), можно просмотреть их список.

```bash
# Список всех сертификатов в виде таблицы
micropki ca list-certs

# Фильтрация по статусу (valid, revoked, expired)
micropki ca list-certs --status valid

# Вывод в формате JSON или CSV
micropki ca list-certs --format json
micropki ca list-certs --format csv
```

### Просмотр конкретного сертификата по серийному номеру

```bash
micropki ca show-cert 0x6521745cca871a45325873c792719
```

## HTTP репозиторий

MicroPKI включает простой HTTP‑сервер для получения сертификатов и информации о состоянии.

### Запуск сервера

```bash
micropki repo serve --host 127.0.0.1 --port 8080 --out-dir ./pki
```

Сервер будет работать до нажатия `Ctrl+C`. Все запросы логируются в консоль (или в файл, если указан `--log-file`).

### Примеры запросов

```bash
# Получить сертификат по серийному номеру
curl http://127.0.0.1:8080/certificate/0x6521745cca871a45325873c792719

# Получить корневой сертификат
curl http://127.0.0.1:8080/ca/root

# Получить промежуточный сертификат
curl http://127.0.0.1:8080/ca/intermediate

# CRL (пока заглушка, будет реализован в Sprint 4)
curl http://127.0.0.1:8080/crl
```

### Примечания

- Серийный номер можно указывать как с префиксом `0x`, так и без него.
- Сервер возвращает PEM‑кодированные сертификаты с Content‑Type `application/x-pem-file`.
- Для удобства тестирования добавлены CORS‑заголовки (`Access-Control-Allow-Origin: *`).



## Запуск тестов

```bash
pip install pytest
pytest tests/ -v
```
Все тесты должны проходить успешно (19 тестов в Sprint 2).


## Параметры команд

### `ca init` (Sprint 1)

| Аргумент | Описание | Пример |
|----------|----------|--------|
| `--subject` | Distinguished Name (DN) в формате `/CN=...` или `CN=...,O=...` | `/CN=My Root CA` |
| `--key-type` | Тип ключа: `rsa` или `ecc` (по умолчанию `rsa`) | `ecc` |
| `--key-size` | Размер ключа: для RSA – 4096, для ECC – 384 (по умолчанию 4096) | `4096` |
| `--passphrase-file` | Путь к файлу с парольной фразой для шифрования ключа | `./secrets/pass.txt` |
| `--out-dir` | Директория для вывода (по умолчанию `./pki`) | `./pki` |
| `--validity-days` | Срок действия сертификата в днях (по умолчанию 3650) | `7300` |
| `--log-file` | Путь к файлу лога (если не указан – логи в stderr) | `./logs/ca-init.log` |
| `--force` | Перезаписывать существующие файлы | `--force` |

### `ca issue-intermediate` (Sprint 2)

| Аргумент | Описание | Пример |
|----------|----------|--------|
| `--root-cert` | Путь к сертификату корневого CA (PEM) | `./pki/certs/ca.cert.pem` |
| `--root-key` | Путь к зашифрованному ключу корневого CA (PEM) | `./pki/private/ca.key.pem` |
| `--root-pass-file` | Файл с парольной фразой для ключа корневого CA | `./pass.txt` |
| `--subject` | Distinguished Name для промежуточного CA | `CN=Intermediate CA,O=MicroPKI` |
| `--key-type` | Тип ключа: `rsa` (4096) или `ecc` (384) | `rsa` |
| `--key-size` | Размер ключа (должен соответствовать типу) | `4096` |
| `--passphrase-file` | Файл с парольной фразой для ключа промежуточного CA | `./int_pass.txt` |
| `--out-dir` | Директория для вывода (по умолчанию `./pki`) | `./pki` |
| `--validity-days` | Срок действия сертификата (по умолчанию 1825) | `1825` |
| `--pathlen` | Ограничение длины цепочки (по умолчанию `0`) | `0` |
| `--log-file` | Путь к файлу лога | `./logs/intermediate.log` |
| `--force` | Перезаписывать существующие файлы | `--force` |

### `ca issue-cert` (Sprint 2)

| Аргумент | Описание | Пример |
|----------|----------|--------|
| `--ca-cert` | Путь к сертификату CA (промежуточного или корневого) | `./pki/certs/intermediate.cert.pem` |
| `--ca-key` | Путь к зашифрованному ключу CA | `./pki/private/intermediate.key.pem` |
| `--ca-pass-file` | Файл с парольной фразой для ключа CA | `./int_pass.txt` |
| `--template` | Тип сертификата: `server`, `client`, `code_signing` | `server` |
| `--subject` | Distinguished Name для конечного сертификата | `CN=example.com` |
| `--san` | Subject Alternative Name (можно указать несколько) | `dns:example.com` `ip:192.168.1.1` |
| `--csr` | (Опционально) Внешний CSR в формате PEM | `./request.csr` |
| `--out-dir` | Директория для вывода (по умолчанию `./pki/certs`) | `./certs` |
| `--validity-days` | Срок действия сертификата (по умолчанию 365) | `365` |
| `--log-file` | Путь к файлу лога | `./logs/issue.log` |

### `ca verify-chain` (Sprint 2)

| Аргумент | Описание | Пример |
|----------|----------|--------|
| `--leaf` | Путь к конечному сертификату (PEM) | `./certs/example.com.cert.pem` |
| `--intermediate` | (Опционально) Путь к сертификату промежуточного CA | `./pki/certs/intermediate.cert.pem` |
| `--root` | Путь к сертификату корневого CA | `./pki/certs/ca.cert.pem` |

### `ca verify` (Sprint 1)

| Аргумент | Описание | Пример |
|----------|----------|--------|
| `--cert` | Путь к сертификату для проверки (только самоподписанный) | `./pki/certs/ca.cert.pem` |


## Конфигурационный файл

MicroPKI поддерживает файл `micropki.conf` в формате YAML. Пример:

```yaml
pki_dir: ./pki
host: 0.0.0.0
port: 8080
log_level: INFO
```

Параметры, заданные в командной строке, имеют приоритет над конфигурационным файлом.

## Проверка статуса репозитория
```bash
micropki repo status
```
Выводит, запущен ли HTTP сервер на указанном (или настроенном) хосте и порту.

## Примечания по безопасности

- Приватные ключи корневого и промежуточного CA хранятся в зашифрованном виде (AES-256).
- Ключи конечных сущностей сохраняются незашифрованными с правами `600`. Будьте внимательны с их хранением.
- Парольные фразы не выводятся в логах.
- На Unix-системах для директории `private` устанавливаются права `700`.