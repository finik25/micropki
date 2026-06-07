
# MicroPKI

Учебный проект по созданию минимальной, но полной инфраструктуры публичных ключей (PKI).  
Реализован на Python с использованием библиотеки `cryptography` (версия 48.0.0) и `asn1crypto` (1.5.1).

## Возможности

- Создание корневого (Root) и промежуточного (Intermediate) удостоверяющих центров
- Выпуск сертификатов по шаблонам: `server`, `client`, `code_signing`, `ocsp_signer`
- Поддержка Subject Alternative Names (SAN): dns, ip, email, uri
- Проверка цепочки сертификатов
- Отзыв сертификатов и генерация CRL (Certificate Revocation List) согласно RFC 5280
- **OCSP-ответчик** (Online Certificate Status Protocol) с поддержкой nonce, кэшированием и полным логированием
- HTTP репозиторий для выдачи сертификатов, CRL и OCSP-ответов
- Шифрование приватных ключей CA (PKCS#8, AES-256)
- Поддержка внешних CSR (опционально)
- Логирование операций (текст/JSON)

## Структура проекта

```
micropki/
├── micropki/              # Основной пакет
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py             # Парсер командной строки
│   ├── ca.py              # Логика CA (инициализация, выпуск, цепочки)
│   ├── certificates.py    # Создание X.509 сертификатов, CSR, шаблоны, SAN
│   ├── crl.py             # Генерация CRL
│   ├── revocation.py      # Отзыв сертификатов
│   ├── crypto_utils.py    # Генерация и шифрование ключей
│   ├── database.py        # Работа с SQLite (схема, миграции)
│   ├── repository.py      # HTTP репозиторий (Flask)
│   ├── ocsp.py            # Парсинг и формирование OCSP-запросов/ответов
│   ├── ocsp_responder.py  # Flask‑приложение OCSP-ответчика с кэшированием
│   ├── logger.py          # Настройка логирования
│   └── config.py          # Конфигурация (YAML)
├── tests/                 # Модульные тесты (pytest)
├── requirements.txt
├── setup.py
├── pytest.ini
└── README.md
```

## Требования

- Python 3.8 или выше
- Библиотеки: `cryptography>=42.0.0`, `asn1crypto>=1.5.0`, `Flask>=2.0`, `pytest>=6.0`, `pyyaml>=6.0`
- OpenSSL (для проверки CRL и OCSP, опционально)

## Установка

1. Клонируйте репозиторий и перейдите в папку проекта:
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
    --validity-days 3650 `
    --force
```

После выполнения в директории `pki` появятся:
- `private/ca.key.pem` – зашифрованный приватный ключ (PEM, PKCS#8)
- `certs/ca.cert.pem` – самоподписанный сертификат
- `policy.txt` – текстовый документ политики CA
- `crl/` – директория для будущих CRL

Проверка с помощью OpenSSL:
```bash
openssl x509 -in pki/certs/ca.cert.pem -text -noout
openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/ca.cert.pem
```

### 2. Создание промежуточного CA (Intermediate)

```bash
echo "intsecret" > int_pass.txt

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
    --pathlen 0 `
    --force
```

Будут созданы:
- `pki/private/intermediate.key.pem` (зашифрован)
- `pki/certs/intermediate.cert.pem`

### 3. Выпуск конечных сертификатов (end-entity)

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
    --validity-days 365 `
    --force
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
    --out-dir ./certs `
    --force
```

#### Сертификат для подписи кода
```bash
micropki ca issue-cert `
    --ca-cert ./pki/certs/intermediate.cert.pem `
    --ca-key ./pki/private/intermediate.key.pem `
    --ca-pass-file int_pass.txt `
    --template code_signing `
    --subject "CN=MicroPKI Code Signer" `
    --out-dir ./certs `
    --force
```

### 4. Отзыв сертификата

```bash
# Отозвать сертификат по серийному номеру
micropki ca revoke 0x2A7F... --reason keyCompromise

# С указанием причины и без подтверждения
micropki ca revoke 0x3B8E... --reason superseded --force
```

Поддерживаемые причины отзыва: `unspecified`, `keyCompromise`, `cACompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `certificateHold`, `removeFromCRL`, `privilegeWithdrawn`, `aACompromise`.

### 5. Генерация CRL

```bash
# CRL для промежуточного CA (срок действия 14 дней)
micropki ca gen-crl --ca intermediate --next-update 14 --ca-pass-file int_pass.txt --force

# CRL для корневого CA (7 дней)
micropki ca gen-crl --ca root --next-update 7 --ca-pass-file pass.txt --force
```

CRL сохраняются в `pki/crl/` как `root.crl.pem` и `intermediate.crl.pem`.

### 6. Проверка статуса отзыва

```bash
micropki ca check-revoked 0x2A7F...
```

### 7. Проверка цепочки сертификатов

```bash
micropki ca verify-chain `
    --leaf ./certs/example.com.cert.pem `
    --intermediate ./pki/certs/intermediate.cert.pem `
    --root ./pki/certs/ca.cert.pem
```

### 8. OCSP‑ответчик (Online Certificate Status Protocol)

#### Выпуск сертификата для OCSP‑подписи

```bash
micropki ca issue-ocsp-cert `
    --ca-cert ./pki/certs/intermediate.cert.pem `
    --ca-key ./pki/private/intermediate.key.pem `
    --ca-pass-file int_pass.txt `
    --subject "CN=OCSP Responder" `
    --key-type rsa --key-size 2048 `
    --out-dir ./pki/certs `
    --force
```

#### Запуск OCSP‑сервера

```bash
micropki ocsp serve `
    --host 127.0.0.1 --port 8081 `
    --db-path ./pki/micropki.db `
    --responder-cert ./pki/certs/OCSP_Responder.cert.pem `
    --responder-key ./pki/certs/OCSP_Responder.key.pem `
    --ca-cert ./pki/certs/intermediate.cert.pem `
    --cache-ttl 120 `
    --log-file ./logs/ocsp.log
```

#### Проверка OCSP с помощью OpenSSL

```bash
openssl ocsp -issuer pki/certs/intermediate.cert.pem `
    -cert certs/example.com.cert.pem `
    -url http://127.0.0.1:8081/ocsp `
    -CAfile pki/certs/ca.cert.pem `
    -resp_text -no_nonce
```

**Примечания:**
- OCSP-ответчик поддерживает nonce (защита от повторов) и кэширование ответов с TTL (по умолчанию 60 секунд).
- Для неизвестных сертификатов возвращается HTTP 404 (это допустимо, требования Sprint 5 выполнены).
- Кэширование реализовано через простой in‑memory кэш с блокировкой потока, ключ = (серийный номер, nonce).

### 9. Управление базой данных сертификатов

#### Инициализация базы данных

```bash
micropki db init --out-dir ./pki
```

#### Просмотр списка сертификатов

```bash
micropki ca list-certs
micropki ca list-certs --status valid
micropki ca list-certs --format json
micropki ca list-certs --format csv
```

#### Просмотр конкретного сертификата по серийному номеру

```bash
micropki ca show-cert 0x6521745cca871a45325873c792719
```

### 10. HTTP репозиторий

#### Запуск сервера

```bash
micropki repo serve --host 127.0.0.1 --port 8080 --out-dir ./pki
```

#### Примеры запросов

```bash
# Получить сертификат по серийному номеру
curl http://127.0.0.1:8080/certificate/0x6521745cca871a45325873c792719

# Получить корневой сертификат
curl http://127.0.0.1:8080/ca/root

# Получить промежуточный сертификат
curl http://127.0.0.1:8080/ca/intermediate

# Получить CRL (по умолчанию intermediate)
curl http://127.0.0.1:8080/crl

# Получить CRL корневого CA
curl http://127.0.0.1:8080/crl?ca=root

# Альтернативный путь
curl http://127.0.0.1:8080/crl/root.crl
```

## Запуск тестов

```bash
pip install -e .[test]   # или просто pip install pytest
pytest tests/ -v
```

Все тесты (включая OCSP) должны проходить успешно. Для OCSP требуется наличие OpenSSL в `PATH`.



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
| `--force` | Перезаписывать существующие файлы | `--force` |

### `ca revoke` (Sprint 4)

| Аргумент | Описание | Пример |
|----------|----------|--------|
| `serial` | Серийный номер сертификата (шестнадцатеричный) | `0x2A7F...` |
| `--reason` | Причина отзыва (по умолчанию `unspecified`) | `keyCompromise` |
| `--force` | Пропустить подтверждение | `--force` |
| `--pki-dir` | Корневая директория PKI (по умолчанию `./pki`) | `./pki` |
| `--log-file` | Путь к файлу лога | `./logs/revoke.log` |

### `ca gen-crl` (Sprint 4)

| Аргумент | Описание | Пример |
|----------|----------|--------|
| `--ca` | Какой CA: `root` или `intermediate` | `root` |
| `--next-update` | Дней до следующего обновления CRL (по умолчанию 7) | `14` |
| `--out-file` | Путь для сохранения CRL (опционально) | `./custom.crl.pem` |
| `--ca-pass-file` | Файл с парольной фразой для ключа CA | `pass.txt` |
| `--pki-dir` | Корневая директория PKI (по умолчанию `./pki`) | `./pki` |
| `--force` | Перезаписывать существующий CRL | `--force` |

### `ca check-revoked` (Sprint 4)

| Аргумент | Описание | Пример |
|----------|----------|--------|
| `serial` | Серийный номер сертификата (шестнадцатеричный) | `0x2A7F...` |
| `--pki-dir` | Корневая директория PKI (по умолчанию `./pki`) | `./pki` |

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
- OCSP-сертификат используется для подписи ответов, его приватный ключ хранится **незашифрованным** (требование автоматического запуска). Убедитесь в безопасности файловой системы.

## Известные ограничения

- OCSP-ответчик возвращает `404 Not Found` для неизвестных сертификатов вместо `unknown` (допустимо, RFC не требует строгого поведения).
- Кэширование OCSP не учитывает изменения статуса до истечения TTL (при необходимости можно обновить CRL/OCSP вручную).
- Delta‑CRL не реализованы (только полные CRL).
- AIA расширения в сертификатах не добавляются (опционально).
