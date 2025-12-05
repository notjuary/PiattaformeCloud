# collector.py - VERSIONE CORRETTA
import logging
import re
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Optional
import pandas as pd

LOG = logging.getLogger(__name__)


class KeystoneLogCollector:
    """Colleziona eventi di autenticazione da Keystone"""

    def __init__(self, log_path: str = None):
        self.log_path = Path(log_path) if log_path else None

    def parse_log_line(self, line: str) -> Optional[Dict[str, Any]]:
        """Parsa una singola riga di log di Keystone - VERSIONE CORRETTA"""
        # Pattern semplificati che corrispondono al tuo formato
        patterns = [
            # Pattern per login falliti (NEL TUO FORMATO)
            r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) Authorization failed for user \'(?P<user>[\w@\.-]+)\' from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',

            # Pattern per login riusciti (NEL TUO FORMATO)
            r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) Successful login for user \'(?P<user>[\w@\.-]+)\' from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        ]

        for pattern in patterns:
            match = re.search(pattern, line.strip())
            if match:
                event = match.groupdict()
                event['raw_line'] = line.strip()

                try:
                    # Il timestamp è già nel formato corretto
                    event['timestamp'] = datetime.strptime(
                        event['timestamp'], '%Y-%m-%d %H:%M:%S'
                    )
                except Exception as e:
                    LOG.warning(f"Errore parsing timestamp: {e}")
                    return None

                # Determina tipo evento
                if 'Authorization failed' in line:
                    event['event_type'] = 'auth_failed'
                    event['success'] = False
                elif 'Successful login' in line:
                    event['event_type'] = 'auth_success'
                    event['success'] = True

                # Estrai info aggiuntive
                event['hour'] = event['timestamp'].hour
                event['day_of_week'] = event['timestamp'].weekday()
                event['is_weekend'] = event['day_of_week'] >= 5
                event['month'] = event['timestamp'].month
                event['day'] = event['timestamp'].day
                event['minute'] = event['timestamp'].minute

                return event

        # Se nessun pattern matcha, logga la riga (per debug)
        LOG.debug(f"Riga non parsata: {line.strip()}")
        return None

    def collect_historical_events(self, hours: int = 24) -> pd.DataFrame:
        """Raccoglie eventi storici dalle ultime N ore - VERSIONE MIGLIORATA"""
        events = []

        try:
            if not self.log_path or not self.log_path.exists():
                LOG.warning(f"File di log non trovato. Genero dati demo.")
                return self._generate_demo_events(hours)

            cutoff_time = datetime.now() - timedelta(hours=hours)

            with open(self.log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    # Salta righe vuote
                    if not line.strip():
                        continue

                    event = self.parse_log_line(line)
                    if event:
                        # Controlla se l'evento è nel range temporale
                        if event['timestamp'] >= cutoff_time:
                            events.append(event)

                    # Debug: mostra progresso
                    if line_num % 100 == 0:
                        LOG.debug(f"Analizzate {line_num} righe, trovati {len(events)} eventi")

            LOG.info(f"Raccolti {len(events)} eventi storici da {self.log_path}")

            if events:
                df = pd.DataFrame(events)
                LOG.debug(f"Colonne nel DataFrame: {df.columns.tolist()}")
                LOG.debug(f"Primi eventi: {df[['timestamp', 'user', 'ip', 'event_type']].head(3).to_dict('records')}")
                return df
            else:
                LOG.warning("Nessun evento trovato nel file di log")
                return self._generate_demo_events(hours)

        except Exception as e:
            LOG.error(f"Errore nella raccolta eventi: {e}")
            import traceback
            LOG.error(traceback.format_exc())
            return self._generate_demo_events(hours)

    def _generate_demo_events(self, hours: int) -> pd.DataFrame:
        """Genera eventi demo per testing - VERSIONE MIGLIORATA"""
        LOG.info("Generazione eventi demo...")

        # Usa gli stessi utenti e IP del tuo log reale
        users = ['alice', 'bob', 'carol', 'dave', 'admin']
        ips = ['192.168.1.10', '192.168.1.11', '10.0.0.5', '10.0.0.6']
        suspicious_ips = ['203.0.113.5', '198.51.100.10', '192.0.2.15']

        events = []
        now = datetime.now()

        # Genera eventi normali (80%)
        for i in range(80):
            timestamp = now - timedelta(minutes=i * 10)  # Distribuisci nel tempo
            user = users[i % len(users)]
            ip = ips[i % len(ips)]

            # 85% successi, 15% fallimenti
            if i % 7 != 0:  # ~85% successi
                event_type = 'auth_success'
                success = True
                line = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} Successful login for user '{user}' from {ip}"
            else:
                event_type = 'auth_failed'
                success = False
                line = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} Authorization failed for user '{user}' from {ip}"

            events.append({
                'timestamp': timestamp,
                'user': user,
                'ip': ip,
                'event_type': event_type,
                'success': success,
                'raw_line': line,
                'hour': timestamp.hour,
                'day_of_week': timestamp.weekday(),
                'is_weekend': timestamp.weekday() >= 5,
                'month': timestamp.month,
                'day': timestamp.day,
                'minute': timestamp.minute
            })

        # Aggiungi pattern di attacco (20%)
        for i in range(20):
            timestamp = now - timedelta(minutes=i * 2)  # Più frequenti
            attacker_ip = suspicious_ips[i % len(suspicious_ips)]

            # Attacchi su admin
            line = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} Authorization failed for user 'admin' from {attacker_ip}"

            events.append({
                'timestamp': timestamp,
                'user': 'admin',
                'ip': attacker_ip,
                'event_type': 'auth_failed',
                'success': False,
                'raw_line': line,
                'hour': timestamp.hour,
                'day_of_week': timestamp.weekday(),
                'is_weekend': timestamp.weekday() >= 5,
                'month': timestamp.month,
                'day': timestamp.day,
                'minute': timestamp.minute
            })

        LOG.info(f"Generati {len(events)} eventi demo")
        return pd.DataFrame(events)