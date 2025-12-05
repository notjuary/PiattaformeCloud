"""
Database module per SQLite
"""
import sqlite3
import logging
from datetime import datetime
from typing import List, Dict, Any

LOG = logging.getLogger(__name__)


def init_db(db_path: str = "security_events.db"):
    """Inizializza il database SQLite"""
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Tabella eventi di autenticazione
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS auth_events
                   (
                       id
                       INTEGER
                       PRIMARY
                       KEY
                       AUTOINCREMENT,
                       timestamp
                       DATETIME
                       NOT
                       NULL,
                       user
                       TEXT
                       NOT
                       NULL,
                       ip
                       TEXT
                       NOT
                       NULL,
                       event_type
                       TEXT
                       NOT
                       NULL,
                       success
                       BOOLEAN
                       NOT
                       NULL,
                       anomaly_score
                       REAL,
                       is_anomaly
                       BOOLEAN,
                       raw_line
                       TEXT,
                       created_at
                       DATETIME
                       DEFAULT
                       CURRENT_TIMESTAMP
                   )
                   ''')

    # Tabella anomalie
    cursor.execute('''
                   CREATE TABLE IF NOT EXISTS anomalies
                   (
                       id
                       INTEGER
                       PRIMARY
                       KEY
                       AUTOINCREMENT,
                       event_id
                       INTEGER,
                       user
                       TEXT
                       NOT
                       NULL,
                       ip
                       TEXT
                       NOT
                       NULL,
                       anomaly_type
                       TEXT
                       NOT
                       NULL,
                       score
                       REAL
                       NOT
                       NULL,
                       description
                       TEXT,
                       resolved
                       BOOLEAN
                       DEFAULT
                       0,
                       created_at
                       DATETIME
                       DEFAULT
                       CURRENT_TIMESTAMP,
                       FOREIGN
                       KEY
                   (
                       event_id
                   ) REFERENCES auth_events
                   (
                       id
                   )
                       )
                   ''')

    # Indici per performance
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_auth_events_timestamp ON auth_events(timestamp)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_auth_events_user ON auth_events(user)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_anomalies_user ON anomalies(user)')

    conn.commit()
    conn.close()

    LOG.info(f"Database inizializzato: {db_path}")
    return True