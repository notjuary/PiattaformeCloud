#!/usr/bin/env python3
"""
Debug del parsing del log
"""
import os
import re


def debug_log_parsing():
    """Debug del formato del log"""
    print("🔍 DEBUG PARSING LOG")
    print("=" * 60)

    # Leggi il file
    log_file = "keystone_example.log"
    if not os.path.exists(log_file):
        print(f"❌ File non trovato: {log_file}")
        return

    with open(log_file, 'r') as f:
        lines = f.readlines()

    print(f"📄 Righe nel file: {len(lines)}")

    # Pattern di test
    patterns = [
        r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) Successful login for user \'(?P<user>[\w@\.-]+)\' from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
        r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) Authorization failed for user \'(?P<user>[\w@\.-]+)\' from (?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})',
    ]

    print("\n🧪 Test pattern sulle prime 10 righe:")
    print("-" * 40)

    for i, line in enumerate(lines[:10]):
        line = line.strip()
        print(f"\nRiga {i + 1}: {line}")

        matched = False
        for pattern in patterns:
            match = re.search(pattern, line)
            if match:
                print(f"  ✅ MATCH con pattern: {pattern[:50]}...")
                print(f"     Timestamp: {match.group('timestamp')}")
                print(f"     User: {match.group('user')}")
                print(f"     IP: {match.group('ip')}")
                matched = True
                break

        if not matched:
            print(f"  ❌ NO MATCH")
            print(f"     Linea: {line}")

    print("\n" + "=" * 60)
    print("💡 CONSIGLI:")
    print("1. Verifica che il formato del timestamp sia YYYY-MM-DD HH:MM:SS")
    print("2. Verifica che non ci siano spazi extra all'inizio/fine")
    print("3. Verifica che le virgolette siano diritte (') non curve (')")


if __name__ == "__main__":
    debug_log_parsing()