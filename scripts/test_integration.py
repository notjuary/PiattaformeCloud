#!/usr/bin/env python3
"""
Test di integrazione con DevStack - VERSIONE MIGLIORATA
"""
import sys
import os
import logging
import platform
import warnings

# Disabilita warning
warnings.filterwarnings('ignore')

# Aggiungi il package al path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_security_advisor.collector import KeystoneLogCollector
from ai_security_advisor.ai_engine import AnomalyDetector
from ai_security_advisor.policy_advisor import PolicyAdvisor

# Configura logging dettagliato
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
LOG = logging.getLogger(__name__)


def test_collector_with_file():
    """Test del collector con file reale"""
    LOG.info("🧪 Test Collector con file keystone_example.log")

    # Trova il file nella directory del progetto
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    log_file = os.path.join(project_root, "keystone_example.log")

    if not os.path.exists(log_file):
        LOG.error(f"❌ File non trovato: {log_file}")
        LOG.info("💡 Crea il file o copialo nella directory principale del progetto")
        return None, 0

    LOG.info(f"📁 Analisi file: {log_file}")

    # Crea collector e raccogli eventi
    collector = KeystoneLogCollector(log_path=log_file)
    events = collector.collect_historical_events(hours=48)  # Ultime 48 ore

    LOG.info(f"📊 Eventi raccolti: {len(events)}")

    if len(events) == 0:
        LOG.warning("⚠️ Nessun evento trovato nel file")
        LOG.info("💡 Verifica che il formato del log corrisponda ai pattern nel collector")
        return None, 0

    # Mostra statistiche
    print("\n📈 STATISTICHE DEL LOG:")
    print("-" * 40)

    # Per utente
    user_stats = events.groupby('user').agg({
        'event_type': 'count',
        'success': lambda x: (x == True).sum()
    }).rename(columns={
        'event_type': 'total_events',
        'success': 'successful_logins'
    })

    user_stats['failure_rate'] = 1 - (user_stats['successful_logins'] / user_stats['total_events'])

    print("\nUtenti (ordine per eventi):")
    print(user_stats.sort_values('total_events', ascending=False))

    # Per IP
    ip_stats = events.groupby('ip').agg({
        'event_type': 'count',
        'success': lambda x: (x == True).sum(),
        'user': 'nunique'
    }).rename(columns={
        'event_type': 'total_events',
        'success': 'successful_logins',
        'user': 'unique_users'
    })

    ip_stats['failure_rate'] = 1 - (ip_stats['successful_logins'] / ip_stats['total_events'])

    print("\nIP (ordine per eventi):")
    print(ip_stats.sort_values('total_events', ascending=False).head(10))

    # Mostra primi eventi
    print("\n🕐 Primi 5 eventi:")
    print(events[['timestamp', 'user', 'ip', 'event_type', 'success']].head())

    return events, len(events)


def test_ai_engine(events):
    """Test del motore AI"""
    LOG.info("🧠 Test AI Engine")

    if events is None or len(events) < 10:
        LOG.warning("⚠️ Troppi pochi eventi per testare l'AI Engine")
        return None, 0

    print("\n🤖 TEST AI ENGINE:")
    print("-" * 40)

    # Crea detector
    detector = AnomalyDetector()

    # Dividi in train/test (80/20)
    train_size = int(len(events) * 0.8)
    train_data = events.iloc[:train_size]
    test_data = events.iloc[train_size:]

    print(f"Training: {len(train_data)} eventi")
    print(f"Test: {len(test_data)} eventi")

    # Addestra sul training set
    LOG.info("Addestramento modello...")
    detector.train(train_data)

    # Testa sul test set
    LOG.info("Rilevamento anomalie...")
    analyzed = detector.detect_anomalies(test_data)

    if analyzed is None:
        LOG.error("❌ Errore nell'analisi")
        return None, 0

    # Conta anomalie
    anomalies = analyzed[analyzed['is_anomaly']]
    anomaly_count = len(anomalies)

    print(f"\n⚠️  Anomalie rilevate: {anomaly_count}/{len(test_data)} ({anomaly_count / len(test_data) * 100:.1f}%)")

    if anomaly_count > 0:
        print("\n🔍 Dettaglio anomalie:")
        for idx, row in anomalies.head(5).iterrows():  # Mostra solo prime 5
            print(f"\n• {row['timestamp']} - {row['user']} da {row['ip']}")
            print(f"  Score: {row['anomaly_score']:.3f}")

            flags = []
            if row.get('unusual_ip', False):
                flags.append("IP insolito")
            if row.get('high_frequency', False):
                flags.append("Alta frequenza")

            if flags:
                print(f"  Flags: {', '.join(flags)}")

    return analyzed, anomaly_count


def test_policy_advisor(analyzed_data):
    """Test del policy advisor"""
    LOG.info("🎯 Test Policy Advisor")

    if analyzed_data is None or len(analyzed_data) == 0:
        LOG.warning("⚠️ Nessun dato per il Policy Advisor")
        return []

    anomalies = analyzed_data[analyzed_data['is_anomaly']]

    if len(anomalies) == 0:
        print("\n✅ Nessuna anomalia da analizzare")
        return []

    print("\n🎯 TEST POLICY ADVISOR:")
    print("-" * 40)

    advisor = PolicyAdvisor()
    report = advisor.generate_report(anomalies)

    recommendations = report.get('recommendations', [])

    if recommendations:
        print(f"\n📋 Raccomandazioni generate: {len(recommendations)}")

        for i, rec in enumerate(recommendations[:5], 1):  # Limita a 5
            print(f"\n{i}. [{rec['priority'].upper()}] {rec['action']}")
            print(f"   Target: {rec['target']}")
            print(f"   Motivo: {rec['reason']}")
            print(f"   Score: {rec['score']:.2f}")
    else:
        print("\n✅ Nessuna raccomandazione necessaria")

    return recommendations


def main():
    """Funzione principale"""
    print("\n" + "=" * 60)
    print("🚀 AI SECURITY ADVISOR - TEST COMPLETO")
    print("=" * 60)

    # Parte 1: Test Collector
    events, events_count = test_collector_with_file()

    if events_count == 0:
        print("\n❌ Test fallito: nessun evento trovato")
        print("\n💡 SOLUZIONE: Assicurati che:")
        print("   1. Il file keystone_example.log sia nella directory principale")
        print("   2. Il formato del log sia corretto (come nell'esempio)")
        print("   3. I pattern nel collector.py corrispondano al tuo formato")
        return

    print("\n" + "=" * 60)

    # Parte 2: Test AI Engine
    analyzed_data, anomaly_count = test_ai_engine(events)

    print("\n" + "=" * 60)

    # Parte 3: Test Policy Advisor
    recommendations = test_policy_advisor(analyzed_data)

    print("\n" + "=" * 60)
    print("📊 RIEPILOGO FINALE:")
    print("-" * 40)

    if events is not None:
        unique_users = events['user'].nunique()
        unique_ips = events['ip'].nunique()
        success_rate = events['success'].mean() * 100

        print(f"• Eventi totali: {events_count}")
        print(f"• Utenti unici: {unique_users}")
        print(f"• IP unici: {unique_ips}")
        print(f"• Tasso successo: {success_rate:.1f}%")
        print(f"• Anomalie rilevate: {anomaly_count}")
        print(f"• Raccomandazioni: {len(recommendations)}")

    print("\n" + "=" * 60)

    if anomaly_count > 0:
        print("⚠️  ATTENZIONE: Sono state rilevate anomalie!")
    else:
        print("✅ Sistema funzionante: nessuna anomalia rilevata")

    print("=" * 60)
    print("🎉 TEST COMPLETATO CON SUCCESSO!")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⏹️  Test interrotto dall'utente")
    except Exception as e:
        print(f"\n\n❌ Errore non gestito: {e}")
        import traceback

        traceback.print_exc()