#!/usr/bin/env python3
"""
AI Security Advisor - Main entry point
"""

import sys
import os

# Aggiungi la directory del progetto al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ai_security_advisor.collector import KeystoneLogCollector
from ai_security_advisor.ai_engine import AnomalyDetector
from ai_security_advisor.policy_advisor import PolicyAdvisor

# Configurazione logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('ai_security_advisor.log'),
        logging.StreamHandler()
    ]
)
LOG = logging.getLogger(__name__)

class AISecurityAdvisor:
    """Orchestratore principale del sistema"""

    def __init__(self, config_path: str = "config/config.yaml"):
        self.config = self.load_config(config_path)
        self.collector = KeystoneLogCollector(
            log_path=self.config.get('log_path', '/opt/stack/logs/keystone.log')
        )
        self.detector = AnomalyDetector()
        self.advisor = PolicyAdvisor(self.config.get('policy', {}))

    def load_config(self, config_path: str) -> dict:
        """Carica configurazione da YAML"""
        default_config = {
            'log_path': '/opt/stack/logs/keystone.log',
            'model_path': 'models/trained_model.pkl',
            'history_hours': 168,  # 7 giorni
            'update_interval_minutes': 5,
            'policy': {
                'risk_threshold': 0.7,
                'mfa_threshold': 0.5
            }
        }

        if Path(config_path).exists():
            with open(config_path, 'r') as f:
                user_config = yaml.safe_load(f)
                default_config.update(user_config)

        return default_config

    def train_initial_model(self):
        """Addestra il modello iniziale su dati storici"""
        LOG.info("Addestramento modello iniziale...")

        # Raccogli dati storici
        historical_data = self.collector.collect_historical_events(
            hours=self.config['history_hours']
        )

        if len(historical_data) > 0:
            self.detector.train(historical_data)

            # Salva modello
            model_path = self.config.get('model_path', 'models/trained_model.pkl')
            Path(model_path).parent.mkdir(parents=True, exist_ok=True)
            self.detector.save_model(model_path)
            LOG.info(f"Modello addestrato su {len(historical_data)} eventi storici")
        else:
            LOG.warning("Nessun dato storico disponibile per l'addestramento")

    def run_once(self):
        """Esegue una singola analisi"""
        LOG.info("Avvio analisi...")

        # Raccogli eventi recenti (ultima ora)
        events = self.collector.collect_historical_events(hours=1)

        if len(events) == 0:
            LOG.info("Nessun evento recente trovato")
            return

        # Rileva anomalie
        analyzed_events = self.detector.detect_anomalies(events)

        # Filtra anomalie
        anomalies = analyzed_events[analyzed_events['is_anomaly']]

        if len(anomalies) > 0:
            LOG.warning(f"Rilevate {len(anomalies)} anomalie!")

            # Genera raccomandazioni
            report = self.advisor.generate_report(anomalies)

            # Logga le raccomandazioni
            for rec in report.get('recommendations', []):
                LOG.info(f"RACCOMANDAZIONE [{rec['priority'].upper()}]: {rec['action']} per {rec['target']} - {rec['reason']}")

            # Salva report
            self.save_report(report)
        else:
            LOG.info("Nessuna anomalia rilevata")

    def save_report(self, report: dict):
        """Salva report su file"""
        import json

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir = Path("reports")
        report_dir.mkdir(exist_ok=True)

        report_file = report_dir / f"security_report_{timestamp}.json"

        with open(report_file, 'w') as f:
            json.dump(report, f, indent=2, default=str)

        LOG.info(f"Report salvato in {report_file}")

def main():
    parser = argparse.ArgumentParser(description="AI Security Advisor per OpenStack Keystone")
    parser.add_argument('--train', action='store_true', help='Addestra modello su dati storici')
    parser.add_argument('--once', action='store_true', help='Esegui analisi una volta')
    parser.add_argument('--config', default='config/config.yaml', help='Percorso file configurazione')

    args = parser.parse_args()

    advisor = AISecurityAdvisor(args.config)

    if args.train:
        advisor.train_initial_model()
    else:
        advisor.run_once()

if __name__ == "__main__":
    main()