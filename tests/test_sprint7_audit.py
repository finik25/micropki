import pytest
import tempfile
import json
from pathlib import Path
from micropki.audit import AuditLogger, init_audit

def test_audit_log_and_integrity():
    with tempfile.TemporaryDirectory() as tmpdir:
        audit_dir = Path(tmpdir) / 'audit'
        logger = AuditLogger(audit_dir)
        # Логируем несколько записей
        h1 = logger.log('AUDIT', 'test_op', 'success', 'first', {'a':1})
        h2 = logger.log('INFO', 'test_op2', 'failure', 'second', {'b':2})
        # Проверяем, что цепочка корректна
        result = logger.verify_all()
        assert result['valid'] is True
        # Читаем записи
        records = logger.query()
        assert len(records) == 2
        assert records[0]['integrity']['hash'] == h1
        # Модифицируем лог
        with open(logger.log_path, 'r+') as f:
            content = f.read()
            # меняем первый символ
            new_content = 'X' + content[1:]
            f.seek(0)
            f.write(new_content)
        # Повторная проверка должна обнаружить ошибку
        result2 = logger.verify_all()
        assert result2['valid'] is False

def test_audit_query_filters():
    with tempfile.TemporaryDirectory() as tmpdir:
        audit_dir = Path(tmpdir) / 'audit'
        logger = AuditLogger(audit_dir)
        logger.log('AUDIT', 'issue', 'success', 'cert1', {'serial':'0x111'})
        logger.log('AUDIT', 'revoke', 'success', 'cert1 revoked', {'serial':'0x111'})
        logger.log('INFO', 'issue', 'failure', 'cert2 failed', {'serial':'0x222'})
        # Фильтр по уровню
        aud = logger.query(level='AUDIT')
        assert len(aud) == 2
        # Фильтр по операции
        rev = logger.query(operation='revoke')
        assert len(rev) == 1
        # Фильтр по серийному
        ser = logger.query(serial='0x111')
        assert len(ser) == 2