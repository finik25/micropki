import sqlite3
import datetime
import os
import random
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

SCHEMA_VERSION = 2

def db_exists(db_path):
    return os.path.exists(db_path)

def get_schema_version(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'")
    if not cursor.fetchone():
        conn.close()
        return 0
    cursor.execute("SELECT version FROM schema_version ORDER BY id DESC LIMIT 1")
    row = cursor.fetchone()
    conn.close()
    return row[0] if row else 0

def set_schema_version(db_path, version):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE IF NOT EXISTS schema_version (id INTEGER PRIMARY KEY AUTOINCREMENT, version INTEGER, applied_at TEXT)")
    cursor.execute("INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
                   (version, datetime.datetime.now(datetime.timezone.utc).isoformat()))
    conn.commit()
    conn.close()

def init_db(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            serial_hex TEXT UNIQUE NOT NULL,
            subject TEXT NOT NULL,
            issuer TEXT NOT NULL,
            not_before TEXT NOT NULL,
            not_after TEXT NOT NULL,
            cert_pem TEXT NOT NULL,
            status TEXT NOT NULL,
            revocation_reason TEXT,
            revocation_date TEXT,
            created_at TEXT NOT NULL
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_serial ON certificates(serial_hex)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_status ON certificates(status)')
    conn.commit()
    conn.close()

def _apply_migration(db_path, from_ver, to_ver):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    try:
        if from_ver == 0 and to_ver == 1:
            init_db(db_path)
        elif from_ver == 1 and to_ver == 2:
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS crl_metadata (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ca_subject TEXT NOT NULL UNIQUE,
                    crl_number INTEGER NOT NULL,
                    last_generated TEXT NOT NULL,
                    next_update TEXT NOT NULL,
                    crl_path TEXT NOT NULL
                )
            ''')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ca_subject ON crl_metadata(ca_subject)')
        else:
            raise ValueError(f"Unknown migration from {from_ver} to {to_ver}")
        conn.commit()
    finally:
        conn.close()
    set_schema_version(db_path, to_ver)

def migrate(db_path, target_version=None):
    if target_version is None:
        target_version = SCHEMA_VERSION
    current = get_schema_version(db_path)
    if current >= target_version:
        return
    for v in range(current, target_version):
        _apply_migration(db_path, v, v+1)

def insert_certificate(db_path, cert, issuer_dn=None, status='valid'):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    serial_hex = hex(cert.serial_number)
    subject = cert.subject.rfc4514_string()
    if issuer_dn is not None:
        issuer = issuer_dn.rfc4514_string()
    else:
        issuer = cert.issuer.rfc4514_string()
    not_before = cert.not_valid_before_utc.isoformat()
    not_after = cert.not_valid_after_utc.isoformat()
    cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM).decode('utf-8')
    created_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
    try:
        cursor.execute('''
            INSERT INTO certificates
            (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (serial_hex, subject, issuer, not_before, not_after, cert_pem, status, created_at))
        conn.commit()
    except sqlite3.IntegrityError as e:
        raise ValueError(f"Duplicate serial number {serial_hex}") from e
    finally:
        conn.close()

def get_cert_by_serial(db_path, serial_hex):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM certificates WHERE serial_hex = ?', (serial_hex,))
    row = cursor.fetchone()
    conn.close()
    return dict(row) if row else None

def list_certs(db_path, status=None, issuer=None, limit=100):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    query = 'SELECT serial_hex, subject, issuer, not_before, not_after, status FROM certificates'
    conditions = []
    params = []
    if status:
        conditions.append('status = ?')
        params.append(status)
    if issuer:
        conditions.append('issuer = ?')
        params.append(issuer)
    if conditions:
        query += ' WHERE ' + ' AND '.join(conditions)
    query += ' ORDER BY not_before DESC LIMIT ?'
    params.append(limit)
    cursor.execute(query, params)
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def update_cert_status(db_path, serial_hex, status, reason=None, date=None):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    rev_date = date if date else datetime.datetime.now(datetime.timezone.utc).isoformat()
    cursor.execute('''
        UPDATE certificates
        SET status = ?, revocation_reason = ?, revocation_date = ?
        WHERE serial_hex = ?
    ''', (status, reason, rev_date, serial_hex))
    conn.commit()
    conn.close()

def generate_unique_serial(db_path):
    while True:
        timestamp = int(datetime.datetime.now(datetime.timezone.utc).timestamp() * 1_000_000)
        random_part = random.getrandbits(64)
        serial = (timestamp << 64) | random_part
        serial = abs(serial)
        if get_cert_by_serial(db_path, hex(serial)) is None:
            return serial

def get_revoked_certs(db_path):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT serial_hex, revocation_date, revocation_reason
        FROM certificates
        WHERE status = 'revoked'
        ORDER BY revocation_date DESC
    ''')
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_crl_metadata(db_path, ca_subject):
    conn = None
    try:
        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM crl_metadata WHERE ca_subject = ?', (ca_subject,))
        row = cursor.fetchone()
        return dict(row) if row else None
    finally:
        if conn:
            conn.close()

def update_crl_metadata(db_path, ca_subject, crl_number, last_generated, next_update, crl_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute('''
        INSERT OR REPLACE INTO crl_metadata
        (ca_subject, crl_number, last_generated, next_update, crl_path)
        VALUES (?, ?, ?, ?, ?)
    ''', (ca_subject, crl_number, last_generated, next_update, crl_path))
    conn.commit()
    conn.close()

def get_next_crl_number(db_path, ca_subject):
    meta = get_crl_metadata(db_path, ca_subject)
    if meta is None:
        return 1
    return meta['crl_number'] + 1

def increment_crl_number(db_path, ca_subject, last_generated, next_update, crl_path):
    new_number = get_next_crl_number(db_path, ca_subject)
    update_crl_metadata(db_path, ca_subject, new_number, last_generated, next_update, crl_path)
    return new_number

def get_revoked_certs_for_issuer(db_path, issuer_dn):
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute('''
        SELECT serial_hex, revocation_date, revocation_reason
        FROM certificates
        WHERE status = 'revoked' AND issuer = ?
        ORDER BY revocation_date DESC
    ''', (issuer_dn,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(row) for row in rows]

def get_cert_object_by_serial(db_path, serial_hex):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT cert_pem FROM certificates WHERE serial_hex = ?", (serial_hex,))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return x509.load_pem_x509_certificate(row[0].encode('utf-8'), default_backend())

def get_cert_object_by_serial_and_issuer(db_path, serial_hex, issuer_dn):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("SELECT cert_pem FROM certificates WHERE serial_hex = ? AND issuer = ?",
                   (serial_hex, issuer_dn))
    row = cursor.fetchone()
    conn.close()
    if not row:
        return None
    return x509.load_pem_x509_certificate(row[0].encode('utf-8'), default_backend())