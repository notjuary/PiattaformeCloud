#!/usr/bin/env python3
"""
Genera un file di log di esempio per test
"""
import os
from datetime import datetime, timedelta
import random


def generate_keystone_example_log(filename="keystone_example.log"):
    """Genera un file di log Keystone di esempio"""

    users = ['alice', 'bob', 'carol', 'dave', 'admin']
    ips_normal = ['192.168.1.10', '192.168.1.11', '10.0.0.5', '10.0.0.6']
    ips_suspicious = ['203.0.113.5', '198.51.100.10', '192.0.2.15']

    events = []
    now = datetime.now()

    # Genera eventi normali (70%)
    for i in range(70):
        timestamp = now - timedelta(minutes=random.randint(0, 1440))  # 24 ore
        user = random.choice(users)
        ip = random.choice(ips_normal)

        if random.random() > 0.1:  # 90% successi
            event_type = 'auth_success'
            success = True
            line = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} Successful login for user '{user}' from {ip}"
        else:
            event_type = 'auth_failed'
            success = False
            line = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} Authorization failed for user '{user}' from {ip}"

        events.append((timestamp, line))

    # Genera eventi sospetti (30%)
    for i in range(30):
        timestamp = now - timedelta(minutes=random.randint(0, 60))  # Ultima ora
        user = 'admin'  # Target admin per attacchi
        ip = random.choice(ips_suspicious)

        # Più fallimenti per IP sospetti
        if random.random() > 0.3:  # 70% fallimenti
            event_type = 'auth_failed'
            success = False
            line = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} Authorization failed for user '{user}' from {ip}"
        else:
            event_type = 'auth_success'
            success = True
            line = f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} Successful login for user '{user}' from {ip}"

        events.append((timestamp, line))

    # Ordina per timestamp
    events.sort(key=lambda x: x[0])

    # Scrivi sul file
    with open(filename, 'w') as f:
        for timestamp, line in events:
            f.write(line + "\n")

    print(f"✅ File generato: {filename}")
    print(f"   Eventi totali: {len(events)}")
    print(f"   Dimensioni: {os.path.getsize(filename)} bytes")

    return filename


if __name__ == "__main__":
    generate_keystone_example_log()