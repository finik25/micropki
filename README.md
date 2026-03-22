
# MicroPKI

Учебный проект по созданию минимальной, но полной инфраструктуры публичных ключей (PKI).  
Реализован в рамках курса по криптографии.

## Текущий статус (Sprint 1)

Выполнена инициализация корневого удостоверяющего центра (Root CA):
- Генерация приватного ключа (RSA-4096 или ECC-P384)
- Создание самоподписанного сертификата X.509 v3 с необходимыми расширениями
- Шифрованное хранение ключа (PKCS#8, AES-256)
- Создание документа политики (`policy.txt`)
- Полное логирование операций

## Структура проекта

```
micropki/
├── micropki/              # Основной пакет
│   ├── __init__.py
│   ├── __main__.py        # Точка входа для python -m micropki
│   ├── cli.py             # Парсер аргументов командной строки
│   ├── ca.py              # Логика инициализации CA
│   ├── certificates.py    # Создание X.509 сертификатов
│   ├── crypto_utils.py    # Генерация и шифрование ключей
│   └── logger.py          # Настройка логирования
├── tests/                 # Модульные тесты (pytest)
│   ├── test_ca.py
│   ├── test_certificates.py
│   └── test_crypto_utils.py
├── requirements.txt       # Зависимости
├── setup.py               # Установка пакета
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

2. Создайте виртуальное окружение (рекомендуется):
   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Linux/macOS
   .venv\Scripts\activate      # Windows
   ```

3. Установите пакет в режиме разработки:
   ```bash
   pip install -e .
   ```


## Использование

### Инициализация корневого CA

1. Создайте файл с парольной фразой (например, `pass.txt`), содержащий одну строку:
   ```bash
   echo "mysecret" > pass.txt
   ```

2. Выполните команду:
   ```bash
   micropki ca init \
       --subject "/CN=My Root CA" \
       --key-type rsa \
       --key-size 4096 \
       --passphrase-file pass.txt \
       --out-dir ./pki \
       --validity-days 3650
   ```

   Для ECC (P-384):
   ```bash
   micropki ca init \
       --subject "CN=ECC Root CA,O=Demo" \
       --key-type ecc \
       --key-size 384 \
       --passphrase-file pass.txt \
       --out-dir ./pki
   ```

3. После успешного выполнения в директории `pki` появятся:
   - `private/ca.key.pem` – зашифрованный приватный ключ (PEM, PKCS#8)
   - `certs/ca.cert.pem` – самоподписанный сертификат (PEM)
   - `policy.txt` – текстовый документ политики CA

### Проверка с помощью OpenSSL

```bash
# Просмотр информации о сертификате
openssl x509 -in pki/certs/ca.cert.pem -text -noout

# Проверка самоподписанного сертификата (должно вернуть OK)
openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/ca.cert.pem
```

### Запуск тестов

```bash
pip install pytest
pytest tests/ -v
```

Все тесты должны пройти успешно (11 passed).

## Параметры команды `ca init`

| Аргумент | Описание | Пример |
|----------|----------|--------|
| `--subject` | Distinguished Name (DN) в формате `/CN=...` или `CN=...,O=...` | `/CN=My Root CA` |
| `--key-type` | Тип ключа: `rsa` или `ecc` (по умолчанию `rsa`) | `ecc` |
| `--key-size` | Размер ключа: для RSA – 4096, для ECC – 384 (по умолчанию 4096) | `4096` |
| `--passphrase-file` | Путь к файлу, содержащему парольную фразу для шифрования ключа | `./secrets/pass.txt` |
| `--out-dir` | Директория для вывода (по умолчанию `./pki`) | `./pki` |
| `--validity-days` | Срок действия сертификата в днях (по умолчанию 3650) | `7300` |
| `--log-file` | Путь к файлу лога (если не указан – логи в stderr) | `./logs/ca-init.log` |
| `--force` | Перезаписывать существующие файлы (опционально) | `--force` |

## Примечания по безопасности

- Приватный ключ всегда хранится в зашифрованном виде (AES-256).
- Файл с парольной фразой должен быть доступен только владельцу.
- В логах парольная фраза никогда не выводится.
- На Unix-системах для директории `private` устанавливаются права `700`, для ключа – `600`.
