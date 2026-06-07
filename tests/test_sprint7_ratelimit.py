import pytest
import tempfile
import threading
import time
import requests
from pathlib import Path
from micropki import ca, database
from micropki.repository import create_app

def test_rate_limiting():
    with tempfile.TemporaryDirectory() as tmpdir:
        pki_dir = Path(tmpdir) / 'pki'
        pki_dir.mkdir()
        database.migrate(str(pki_dir / 'micropki.db'))
        pass_file = pki_dir / 'pass.txt'
        pass_file.write_text('rootpass')
        ca.init_ca('CN=Root', 'rsa', 4096, str(pass_file), str(pki_dir), 365, force=True)

        app = create_app(str(pki_dir), rate_limit=1, rate_burst=2)
        client = app.test_client()

        # Первые 2 запроса должны пройти (делаем их с небольшой задержкой)
        resp1 = client.get('/ca/root')
        assert resp1.status_code == 200
        time.sleep(0.1)  # небольшая задержка
        resp2 = client.get('/ca/root')
        assert resp2.status_code == 200
        # Третий запрос – должен быть ограничен
        resp3 = client.get('/ca/root')
        assert resp3.status_code == 429
        # Подождать 1 секунду – токены восстановятся
        time.sleep(1.1)
        resp4 = client.get('/ca/root')
        assert resp4.status_code == 200