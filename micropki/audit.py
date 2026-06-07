# micropki/audit.py
import json
import hashlib
import datetime
import threading
from pathlib import Path
from typing import Dict, Optional, Any, List

class AuditLogger:
    def __init__(self, audit_dir: Path):
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)   # создаём директорию
        self.log_path = self.audit_dir / 'audit.log'
        self.chain_path = self.audit_dir / 'chain.dat'
        self.lock = threading.Lock()
        self._load_or_init_chain()

    def _load_or_init_chain(self):
        if self.chain_path.exists():
            with open(self.chain_path, 'r') as f:
                self.last_hash = f.read().strip()
        else:
            self.last_hash = '0' * 64

    def _save_chain(self, new_hash: str):
        with open(self.chain_path, 'w') as f:
            f.write(new_hash)

    @staticmethod
    def _canonical_json(obj: Dict) -> str:
        return json.dumps(obj, sort_keys=True, separators=(',', ':'))

    def _compute_hash(self, entry_without_hash: Dict) -> str:
        canonical = self._canonical_json(entry_without_hash)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def log(self,
            level: str,
            operation: str,
            status: str,
            message: str,
            metadata: Optional[Dict[str, Any]] = None) -> str:
        with self.lock:
            # Гарантируем, что директория существует перед записью
            self.audit_dir.mkdir(parents=True, exist_ok=True)
            entry = {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='microseconds') + 'Z',
                "level": level.upper(),
                "operation": operation,
                "status": status,
                "message": message,
                "metadata": metadata or {},
                "integrity": {
                    "prev_hash": self.last_hash,
                    "hash": ""
                }
            }
            # Создаём копию без поля hash для вычисления
            entry_for_hash = entry.copy()
            del entry_for_hash["integrity"]["hash"]
            entry_hash = self._compute_hash(entry_for_hash)
            entry["integrity"]["hash"] = entry_hash
            self.last_hash = entry_hash
            # Запись в файл
            with open(self.log_path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry) + '\n')
            self._save_chain(entry_hash)
        return entry_hash

    def query(self,
              start_time: Optional[str] = None,
              end_time: Optional[str] = None,
              level: Optional[str] = None,
              operation: Optional[str] = None,
              serial: Optional[str] = None,
              verify: bool = False) -> List[Dict]:
        if not self.log_path.exists():
            return []
        records = []
        with open(self.log_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                # Фильтрация
                if start_time and rec.get('timestamp', '') < start_time:
                    continue
                if end_time and rec.get('timestamp', '') > end_time:
                    continue
                if level and rec.get('level') != level:
                    continue
                if operation and rec.get('operation') != operation:
                    continue
                if serial:
                    meta = rec.get('metadata', {})
                    if meta.get('serial') != serial and meta.get('certificate_serial') != serial:
                        continue
                if verify:
                    rec = self._verify_record_integrity(rec) or rec
                records.append(rec)
        return records

    def _verify_record_integrity(self, record: Dict) -> Optional[Dict]:
        """Проверяет одну запись, возвращает запись с добавленным полем 'integrity_ok' или None."""
        if 'integrity' not in record:
            return None
        integrity = record['integrity']
        prev_hash = integrity.get('prev_hash')
        # При пересчёте хеша нужно исключить поле 'hash' из integrity
        # Создаём копию записи без integrity.hash
        record_copy = record.copy()
        record_copy['integrity'] = record_copy['integrity'].copy()
        record_copy['integrity']['hash'] = ''
        # Убираем поле hash
        del record_copy['integrity']['hash']
        computed = self._compute_hash(record_copy)
        if computed != integrity.get('hash'):
            return None
        record['integrity_ok'] = True
        return record

    def verify_all(self) -> Dict[str, Any]:
        if not self.log_path.exists():
            return {'valid': True, 'message': 'Log file does not exist'}
        prev_hash = '0' * 64
        with open(self.log_path, 'r', encoding='utf-8') as f:
            for line_num, line in enumerate(f, start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    return {'valid': False, 'first_bad_index': line_num,
                            'message': f'Invalid JSON at line {line_num}'}
                if 'integrity' not in rec:
                    return {'valid': False, 'first_bad_index': line_num,
                            'message': f'Missing integrity field at line {line_num}'}
                if rec['integrity'].get('prev_hash') != prev_hash:
                    return {'valid': False, 'first_bad_index': line_num,
                            'message': f'Hash chain broken at line {line_num}: expected prev_hash={prev_hash}'}
                # Проверяем хеш текущей записи
                rec_copy = rec.copy()
                rec_copy['integrity'] = rec_copy['integrity'].copy()
                rec_copy['integrity']['hash'] = ''
                del rec_copy['integrity']['hash']
                computed = self._compute_hash(rec_copy)
                if computed != rec['integrity'].get('hash'):
                    return {'valid': False, 'first_bad_index': line_num,
                            'message': f'Hash mismatch at line {line_num}'}
                prev_hash = rec['integrity']['hash']
        # Проверяем последний хеш с chain.dat
        if self.chain_path.exists():
            with open(self.chain_path, 'r') as f:
                saved_hash = f.read().strip()
            if saved_hash != prev_hash:
                return {'valid': False, 'message': 'Final hash does not match chain.dat'}
        return {'valid': True, 'message': 'Audit log integrity verified'}


# Глобальный экземпляр
_audit_logger: Optional[AuditLogger] = None

def init_audit(pki_dir: Path) -> AuditLogger:
    global _audit_logger
    if _audit_logger is None:
        audit_dir = pki_dir / 'audit'
        _audit_logger = AuditLogger(audit_dir)
    return _audit_logger

def get_audit_logger() -> AuditLogger:
    if _audit_logger is None:
        raise RuntimeError("Audit logger not initialized. Call init_audit(pki_dir) first.")
    return _audit_logger

def ensure_audit(pki_dir: Path) -> None:
    """Инициализирует аудит, если он ещё не инициализирован."""
    if _audit_logger is None:
        init_audit(pki_dir)

def audit_log(level: str, operation: str, status: str, message: str, metadata: Optional[Dict] = None) -> str:
    return get_audit_logger().log(level, operation, status, message, metadata)