import re
import pandas as pd
from datetime import datetime
#"/var/log/keystone/keystone.log" # Percorso del log Keystone VM

LOG_PATH = "./data/keystone_sample.log" # Percorso del log Keystone Windows

def parse_log_line(line):
    """
    Estrae informazioni da una riga di log.
    Cerca eventi di login (successo o fallimento), utente, IP, timestamp.
    """
    # Esempio di riga: "2025-11-18 12:34:56 Authorization failed for user 'alice' from 192.168.1.5"
    pattern = r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}).*(?P<event>Authorization failed|Successful login).*user ['\"](?P<user>\w+)['\"].*from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    match = re.search(pattern, line)
    if match:
        return {
            "timestamp": match.group("timestamp"),
            "event": match.group("event"),
            "user": match.group("user"),
            "ip": match.group("ip")
        }
    return None

def collect_events(log_path=LOG_PATH):
    """
    Legge il file di log e restituisce un DataFrame con gli eventi rilevanti.
    """
    events = []
    try:
        with open(log_path, "r") as f:
            for line in f:
                parsed = parse_log_line(line)
                if parsed:
                    events.append(parsed)
    except FileNotFoundError:
        print(f"Log file not found: {log_path}")
        return pd.DataFrame()

    df = pd.DataFrame(events)
    if not df.empty:
        df["timestamp"] = pd.to_datetime(df["timestamp"])
        df["hour"] = df["timestamp"].dt.hour
    return df
