#!/usr/bin/env python3
"""
Auto-tuning per l'AI Security Advisor
Trova i parametri ottimali per il modello
"""
import sys
import os
import pandas as pd
import numpy as np
from sklearn.model_selection import GridSearchCV, TimeSeriesSplit
from sklearn.ensemble import IsolationForest
import logging

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ai_security_advisor.collector import KeystoneLogCollector
from ai_security_advisor.ai_engine import AnomalyDetector

logging.basicConfig(level=logging.INFO)
LOG = logging.getLogger(__name__)


def load_training_data(log_path=None, hours=168):
    """Carica dati per il training"""
    if log_path and os.path.exists(log_path):
        collector = KeystoneLogCollector(log_path)
        events = collector.collect_historical_events(hours)
    else:
        # Usa dati sintetici
        collector = KeystoneLogCollector()
        events = collector.collect_historical_events(hours)

    LOG.info(f"Dati caricati: {len(events)} eventi")
    return events


def auto_tune_parameters(events):
    """Esegue grid search per trovare i parametri ottimali"""
    if len(events) < 100:
        LOG.warning(f"Troppi pochi dati ({len(events)}) per il tuning. Usa almeno 100 eventi.")
        return None

    # Prepara features
    detector = AnomalyDetector()
    features = detector.prepare_features(events)

    if features.empty:
        LOG.error("Impossibile estrarre features")
        return None

    # Definisci i parametri da testare
    param_grid = {
        'n_estimators': [50, 100, 200],
        'max_samples': ['auto', 100, 200],
        'contamination': [0.01, 0.05, 0.1, 0.2],
        'max_features': [0.5, 0.8, 1.0],
        'bootstrap': [True, False]
    }

    # Usa TimeSeriesSplit per dati temporali
    tscv = TimeSeriesSplit(n_splits=3)

    # Grid Search
    LOG.info("Inizio grid search...")
    grid_search = GridSearchCV(
        IsolationForest(random_state=42),
        param_grid,
        cv=tscv,
        scoring='accuracy',
        n_jobs=-1,
        verbose=1
    )

    grid_search.fit(features)

    LOG.info(f"Migliori parametri: {grid_search.best_params_}")
    LOG.info(f"Miglior score: {grid_search.best_score_:.3f}")

    return grid_search.best_params_


def main():
    """Funzione principale"""
    print("🔧 Auto-tuning AI Security Advisor")
    print("=" * 50)

    # Carica dati
    events = load_training_data(hours=168)

    if len(events) < 100:
        print("❌ Troppi pochi dati per il tuning")
        return

    # Esegui auto-tuning
    best_params = auto_tune_parameters(events)

    if best_params:
        print("\n✅ Auto-tuning completato!")
        print("\n📊 Migliori parametri trovati:")
        for param, value in best_params.items():
            print(f"  {param}: {value}")

        # Crea configurazione suggerita
        print("\n💡 Configurazione suggerita per ai_engine.py:")
        print(f"""
        self.model = IsolationForest(
            n_estimators={best_params.get('n_estimators', 100)},
            max_samples={best_params.get('max_samples', 'auto')},
            contamination={best_params.get('contamination', 0.1)},
            max_features={best_params.get('max_features', 1.0)},
            bootstrap={best_params.get('bootstrap', False)},
            random_state=42
        )
        """)
    else:
        print("❌ Auto-tuning fallito")


if __name__ == "__main__":
    main()