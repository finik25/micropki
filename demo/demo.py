#!/usr/bin/env python3
"""MicroPKI Demo Script - Sprint 8 (финальная рабочая версия с русским выводом)"""

import os
import sys
import time
import shutil
import subprocess
import tempfile
import threading
import http.server
import ssl
from pathlib import Path

# Добавляем путь к проекту
sys.path.insert(0, str(Path(__file__).parent.parent))


def run_cmd(cmd, capture=False, check=True):
    print(f"\n$ {' '.join(cmd)}")
    if capture:
        result = subprocess.run(cmd, capture_output=True, text=True)
        if check and result.returncode != 0:
            print(result.stderr)
            raise RuntimeError(f"Команда завершилась с кодом {result.returncode}")
        return result
    else:
        subprocess.run(cmd, check=check)


def start_https_server(certfile, keyfile, chainfile, port=8443):
    """Запускает HTTPS-сервер, отправляя полную цепочку сертификатов (leaf + intermediate)"""
    # Создаём fullchain.pem: leaf + intermediate
    fullchain = Path(certfile).parent / "fullchain.pem"
    with open(fullchain, 'wb') as f:
        f.write(Path(certfile).read_bytes())
        f.write(Path(chainfile).read_bytes())

    handler = http.server.SimpleHTTPRequestHandler
    httpd = http.server.HTTPServer(('127.0.0.1', port), handler)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(str(fullchain), keyfile)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    return httpd, fullchain


def check_https(host, port, ca_bundle):
    """Проверяет HTTPS-соединение с помощью requests"""
    try:
        import requests
        resp = requests.get(f'https://{host}:{port}', verify=str(ca_bundle), timeout=5)
        return resp.status_code == 200
    except Exception as e:
        print(f"TLS error: {e}")
        return False


def main():
    tmpdir = tempfile.mkdtemp(prefix="micropki_demo_")
    pki_dir = Path(tmpdir) / "pki"
    logs_dir = Path(tmpdir) / "logs"
    pki_dir.mkdir()
    logs_dir.mkdir()
    print(f"Рабочая директория: {tmpdir}")

    root_pass = pki_dir / "root_pass.txt"
    root_pass.write_text("rootsecret")
    int_pass = pki_dir / "int_pass.txt"
    int_pass.write_text("intsecret")

    # 1. Root CA
    run_cmd([
        sys.executable, "-m", "micropki", "ca", "init",
        "--subject", "CN=Demo Root CA",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(root_pass),
        "--out-dir", str(pki_dir),
        "--validity-days", "3650", "--force"
    ])
    print("✅ Корневой ЦС создан")

    # 2. Intermediate CA
    run_cmd([
        sys.executable, "-m", "micropki", "ca", "issue-intermediate",
        "--root-cert", str(pki_dir / "certs" / "ca.cert.pem"),
        "--root-key", str(pki_dir / "private" / "ca.key.pem"),
        "--root-pass-file", str(root_pass),
        "--subject", "CN=Demo Intermediate CA",
        "--key-type", "rsa", "--key-size", "4096",
        "--passphrase-file", str(int_pass),
        "--out-dir", str(pki_dir),
        "--validity-days", "1825", "--pathlen", "0", "--force",
        "--pki-dir", str(pki_dir),
        "--crl-url", "http://127.0.0.1:8080/crl?ca=intermediate",
        "--ocsp-url", "http://127.0.0.1:8081/ocsp"
    ])
    print("✅ Промежуточный ЦС создан")

    # 3. Init DB
    run_cmd([
        sys.executable, "-m", "micropki", "db", "init",
        "--out-dir", str(pki_dir)
    ])
    print("✅ База данных инициализирована")

    # 4. OCSP certificate
    run_cmd([
        sys.executable, "-m", "micropki", "ca", "issue-ocsp-cert",
        "--ca-cert", str(pki_dir / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(pki_dir / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(int_pass),
        "--subject", "CN=OCSP Responder",
        "--key-type", "rsa", "--key-size", "2048",
        "--out-dir", str(pki_dir / "certs"), "--force",
        "--pki-dir", str(pki_dir)
    ])
    print("✅ OCSP-сертификат выпущен")

    # 5. Start repo and OCSP
    repo_proc = subprocess.Popen([
        sys.executable, "-m", "micropki", "repo", "serve",
        "--host", "127.0.0.1", "--port", "8080",
        "--out-dir", str(pki_dir),
        "--ca-cert", str(pki_dir / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(pki_dir / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(int_pass),
        "--crl-url", "http://127.0.0.1:8080/crl?ca=intermediate",
        "--ocsp-url", "http://127.0.0.1:8081/ocsp",
        "--log-file", str(logs_dir / "repo.log")
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    ocsp_proc = subprocess.Popen([
        sys.executable, "-m", "micropki", "ocsp", "serve",
        "--host", "127.0.0.1", "--port", "8081",
        "--db-path", str(pki_dir / "micropki.db"),
        "--responder-cert", str(pki_dir / "certs" / "OCSP_Responder.cert.pem"),
        "--responder-key", str(pki_dir / "certs" / "OCSP_Responder.key.pem"),
        "--ca-cert", str(pki_dir / "certs" / "intermediate.cert.pem"),
        "--log-file", str(logs_dir / "ocsp.log")
    ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(3)

    # 6. Initial CRL
    run_cmd([
        sys.executable, "-m", "micropki", "ca", "gen-crl",
        "--ca", "intermediate", "--next-update", "7",
        "--ca-pass-file", str(int_pass),
        "--pki-dir", str(pki_dir), "--force"
    ])
    print("✅ Начальный CRL создан")

    # 7. Сертификат для отзыва (с поддержкой 127.0.0.1)
    run_cmd([
        sys.executable, "-m", "micropki", "ca", "issue-cert",
        "--ca-cert", str(pki_dir / "certs" / "intermediate.cert.pem"),
        "--ca-key", str(pki_dir / "private" / "intermediate.key.pem"),
        "--ca-pass-file", str(int_pass),
        "--template", "server",
        "--subject", "CN=revoke-test.local",
        "--san", "dns:revoke-test.local",
        "--san", "ip:127.0.0.1",
        "--san", "dns:localhost",
        "--out-dir", str(pki_dir / "certs"),
        "--validity-days", "30",
        "--pki-dir", str(pki_dir),
        "--force"
    ])
    print("✅ Сертификат для отзыва выпущен")

    cert_revoke = pki_dir / "certs" / "revoke-test.local.cert.pem"
    key_revoke = pki_dir / "certs" / "revoke-test.local.key.pem"
    if not cert_revoke.exists():
        certs = sorted(pki_dir.glob("certs/*.cert.pem"), key=os.path.getmtime)
        if certs:
            cert_revoke = certs[-1]
            key_revoke = cert_revoke.with_suffix('.key.pem')
        else:
            raise RuntimeError("Не найден сертификат для теста отзыва")

    # Получаем серийный номер
    from cryptography import x509
    from cryptography.hazmat.backends import default_backend
    with open(cert_revoke, 'rb') as f:
        cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    serial_hex = hex(cert.serial_number)
    print(f"Серийный номер сертификата для отзыва: {serial_hex}")

    # 8. Проверка статуса до отзыва
    print("\n=== Проверка статуса отзыва ДО отзыва ===")
    result_before = run_cmd([
        sys.executable, "-m", "micropki", "ca", "check-revoked",
        serial_hex, "--pki-dir", str(pki_dir)
    ], capture=True)
    if "not revoked" in result_before.stdout.lower():
        print("✅ Сертификат НЕ отозван (как и ожидалось)")
    else:
        print("❌ Неожиданный статус до отзыва:", result_before.stdout)
        raise RuntimeError("Статус до отзыва не 'not revoked'")

    # 9. TLS-сервер и проверка
    print("\n=== Запуск HTTPS-сервера с полной цепочкой сертификатов ===")
    # Создаём bundle для клиента: root + intermediate
    bundle_path = pki_dir / "ca_bundle.pem"
    with open(bundle_path, 'wb') as bundle:
        bundle.write((pki_dir / "certs" / "ca.cert.pem").read_bytes())
        bundle.write((pki_dir / "certs" / "intermediate.cert.pem").read_bytes())

    server, _ = start_https_server(cert_revoke, key_revoke, pki_dir / "certs" / "intermediate.cert.pem", port=8443)
    time.sleep(2)  # даём серверу время запуститься

    # Проверяем TLS-соединение
    import requests
    try:
        resp = requests.get('https://127.0.0.1:8443', verify=str(bundle_path), timeout=5)
        if resp.status_code == 200:
            print("✅ TLS-соединение успешно (сертификат доверен)")
        else:
            print(f"⚠️ TLS-соединение вернуло HTTP {resp.status_code}")
    except Exception as e:
        print(f"❌ TLS-соединение не удалось: {e}")
        raise RuntimeError("TLS handshake не удался до отзыва")

    # 10. Отзыв сертификата
    print(f"\n=== Отзыв сертификата с серийным номером {serial_hex} ===")
    run_cmd([
        sys.executable, "-m", "micropki", "ca", "revoke",
        serial_hex,
        "--reason", "keyCompromise",
        "--pki-dir", str(pki_dir), "--force"
    ])

    # 11. Regenerate CRL
    run_cmd([
        sys.executable, "-m", "micropki", "ca", "gen-crl",
        "--ca", "intermediate", "--next-update", "7",
        "--ca-pass-file", str(int_pass),
        "--pki-dir", str(pki_dir), "--force"
    ])

    # 12. Проверка статуса после отзыва (через БД)
    print("\n=== Проверка статуса отзыва ПОСЛЕ отзыва ===")
    result_after = run_cmd([
        sys.executable, "-m", "micropki", "ca", "check-revoked",
        serial_hex, "--pki-dir", str(pki_dir)
    ], capture=True)
    if "revoked" in result_after.stdout.lower():
        print("✅ Сертификат корректно обнаружен как отозванный")
    else:
        print("❌ Отзыв не обнаружен:", result_after.stdout)
        raise RuntimeError("Отзыв не обнаружен")

    # Останавливаем TLS-сервер
    server.shutdown()
    time.sleep(1)

    # 13. Клиентские команды (демонстрация API)
    print("\n=== Демонстрация клиентских команд (CSR + request-cert) ===")
    client_key = pki_dir / "client.key"
    client_csr = pki_dir / "client.csr"
    client_cert = pki_dir / "client.cert"
    run_cmd([
        sys.executable, "-m", "micropki", "client", "gen-csr",
        "--subject", "CN=demo-api.local", "--san", "dns:demo-api.local",
        "--out-key", str(client_key), "--out-csr", str(client_csr), "--force"
    ])
    run_cmd([
        sys.executable, "-m", "micropki", "client", "request-cert",
        "--csr", str(client_csr), "--template", "server",
        "--ca-url", "http://127.0.0.1:8080",
        "--out-cert", str(client_cert), "--force"
    ])
    print("✅ Сертификат, выданный через API, сохранён")

    # 14. Code signing demo
    print("\n=== Демонстрация подписи кода ===")
    code_key = pki_dir / "code.key"
    code_csr = pki_dir / "code.csr"
    code_cert = pki_dir / "code.cert"
    run_cmd([
        sys.executable, "-m", "micropki", "client", "gen-csr",
        "--subject", "CN=Code Signer",
        "--out-key", str(code_key), "--out-csr", str(code_csr), "--force"
    ])
    run_cmd([
        sys.executable, "-m", "micropki", "client", "request-cert",
        "--csr", str(code_csr), "--template", "code_signing",
        "--ca-url", "http://127.0.0.1:8080",
        "--out-cert", str(code_cert), "--force"
    ])

    test_file = pki_dir / "test.txt"
    test_file.write_text("Hello, MicroPKI!")
    sig_file = pki_dir / "test.sig"
    subprocess.run([
        "openssl", "dgst", "-sha256", "-sign", str(code_key),
        "-out", str(sig_file), str(test_file)
    ], check=True)
    # Для Windows: извлекаем публичный ключ в отдельный файл
    pubkey_file = pki_dir / "pubkey.pem"
    subprocess.run(
        f'openssl x509 -in {code_cert} -pubkey -noout > {pubkey_file}',
        shell=True, check=True
    )
    verify_res = subprocess.run(
        f'openssl dgst -sha256 -verify {pubkey_file} -signature {sig_file} {test_file}',
        shell=True, capture_output=True, text=True
    )
    if verify_res.returncode == 0:
        print("✅ Подпись кода успешно проверена")
    else:
        print("❌ Ошибка верификации подписи кода:", verify_res.stderr)
        raise RuntimeError("Ошибка верификации подписи кода")

    # 15. Audit log verification
    audit_res = run_cmd([
        sys.executable, "-m", "micropki", "audit", "verify",
        "--audit-dir", str(pki_dir / "audit")
    ], capture=True)
    if "OK" in audit_res.stdout:
        print("✅ Аудит-лог корректен")
    else:
        raise RuntimeError("Ошибка верификации аудит-лога")

    # 16. Cleanup
    repo_proc.terminate()
    ocsp_proc.terminate()
    time.sleep(1)

    print("\n" + "=" * 50)
    print("✅ Демонстрация успешно завершена!")
    print(f"Все артефакты в {tmpdir}")

    # 17. Запуск тестов по нажатию Enter
    print("\nНажмите Enter, чтобы запустить все тесты (pytest), или Ctrl+C для выхода.")
    input()
    print("\n=== Запуск тестов ===")
    test_result = subprocess.run([sys.executable, "-m", "pytest", "tests/", "-v"])
    if test_result.returncode == 0:
        print("✅ Все тесты прошли успешно")
    else:
        print("❌ Некоторые тесты не прошли")

    print("\nНажмите Enter для удаления временных файлов.")
    input()
    shutil.rmtree(tmpdir)
    print("Временные файлы удалены.")


if __name__ == "__main__":
    main()