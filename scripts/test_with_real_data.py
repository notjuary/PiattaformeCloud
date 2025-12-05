#!/usr/bin/env python3
"""
Test con dati reali da DevStack
"""
import sys
import os
import logging
import platform
import json
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_security_advisor.collector import KeystoneLogCollector
from ai_security_advisor.ai_engine import AnomalyDetector
from ai_security_advisor.policy_advisor import PolicyAdvisor

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)


def test_with_devstack():
    """Test con DevStack reale"""
    LOG.info("🧪 Test con DevStack reale")

    # Percorsi per DevStack
    devstack_paths = {
        'log': "/opt/stack/logs/keystone.log",
        'openrc': "/opt/stack/openrc"
    }

    # Verifica se siamo su una VM con DevStack
    if not os.path.exists(devstack_paths['log']):
        LOG.error("❌ DevStack non trovato")
        LOG.info("Questo test deve essere eseguito sulla VM con DevStack")
        return False

    # Carica i log
    collector = KeystoneLogCollector(devstack_paths['log'])
    events = collector.collect_historical_events(hours=24)

    LOG.info(f"📊 Eventi da DevStack: {len(events)}")

    if len(events) < 20:
        LOG.warning("⚠️ Troppi pochi eventi. Genera traffico con:")
        LOG.info("  source /opt/stack/openrc admin admin")
        LOG.info("  openstack token issue")
        LOG.info("  openstack --os-password wrongpass token issue")
        return False

    # Analizza con AI
    detector = AnomalyDetector()

    # Train/Test split
    train_size = int(len(events) * 0.7)
    train_data = events.iloc[:train_size]
    test_data = events.iloc[train_size:]

    LOG.info(f"Training: {len(train_data)} eventi")
    LOG.info(f"Test: {len(test_data)} eventi")

    # Addestra
    detector.train(train_data)

    # Rileva anomalie
    analyzed = detector.detect_anomalies(test_data)
    anomalies = analyzed[analyzed['is_anomaly']]

    LOG.info(f"⚠️  Anomalie rilevate: {len(anomalies)}")

    # Genera raccomandazioni
    advisor = PolicyAdvisor()
    recommendations = advisor.analyze_anomalies(anomalies)

    # Salva report
    report = {
        'timestamp': datetime.now().isoformat(),
        'source': 'devstack',
        'total_events': len(events),
        'anomalies_detected': len(anomalies),
        'anomaly_rate': len(anomalies) / len(events),
        'recommendations': recommendations,
        'sample_anomalies': anomalies[['user', 'ip', 'anomaly_score']].head(5).to_dict('records')
    }

    # Salva su file
    report_file = f"devstack_test_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)

    LOG.info(f"📄 Report salvato: {report_file}")

    # Mostra risultati
    print("\n" + "=" * 60)
    print("📋 REPORT DEVCSTACK")
    print("=" * 60)

    print(f"\n📊 Statistiche:")
    print(f"  • Eventi totali: {len(events)}")
    print(f"  • Anomalie rilevate: {len(anomalies)}")
    print(f"  • Tasso anomalie: {len(anomalies) / len(events) * 100:.1f}%")

    if recommendations:
        print(f"\n🎯 Raccomandazioni: {len(recommendations)}")
        for i, rec in enumerate(recommendations[:3], 1):
            print(f"\n  {i}. [{rec['priority'].upper()}] {rec['action']}")
            print(f"     Target: {rec['target']}")
            print(f"     Motivo: {rec['reason']}")

    return True


def generate_test_traffic():
    """Genera traffico di test per DevStack"""
    LOG.info("🚀 Generazione traffico di test...")

    commands = [
        "openstack token issue > /dev/null 2>&1",
        "openstack user list --limit 3 > /dev/null 2>&1",
        "openstack project list --limit 3 > /dev/null 2>&1",
        # Tentativi falliti
        "openstack --os-password wrongpass token issue 2>/dev/null || true",
        "openstack --os-username wronguser token issue 2>/dev/null || true",
        # Altre operazioni
        "openstack service list --limit 3 > /dev/null 2>&1",
    ]

    for cmd in commands:
        full_cmd = f"source /opt/stack/openrc admin admin && {cmd}"
        os.system(full_cmd)

    LOG.info("Traffico di test generato")


def main():
    """Funzione principale"""
    print("🚀 AI Security Advisor - Test con DevStack reale")
    print("=" * 60)

    # Controlla se siamo su Linux
    if platform.system() != "Linux":
        print("❌ Questo test richiede Linux con DevStack")
        print("💡 Esegui sulla tua VM Ubuntu")
        return

    # Genera traffico di test
    generate_test_traffic()

    # Esegui test
    success = test_with_devstack()

    if success:
        print("\n" + "=" * 60)
        print("✅ Test completato con successo!")
    else:
        print("\n" + "=" * 60)
        print("⚠️  Test completato con avvertenze")


if __name__ == "__main__":
    main()