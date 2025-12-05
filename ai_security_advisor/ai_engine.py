# ai_engine.py
import pickle
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from collections import defaultdict
import logging

# Disabilita alcuni warning
import warnings

warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=UserWarning)

LOG = logging.getLogger(__name__)


class AnomalyDetector:
    """Motore AI per rilevamento anomalie - VERSIONE CORRETTA"""

    def __init__(self, model_path: str = None):
        self.model = IsolationForest(
            n_estimators=50,  # Ottimizzato da auto-tuning
            contamination=0.01,  # Solo 1% anomalie (più conservativo)
            random_state=42,
            max_samples='auto',
            max_features=0.5,  # Usa 50% features
            bootstrap=True,  # Migliore stabilità
            n_jobs=-1  # Usa tutti i core CPU
        )
        self.scaler = StandardScaler()
        self.user_profiles = defaultdict(dict)

        if model_path:
            self.load_model(model_path)

    def prepare_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Prepara features per il modello ML - VERSIONE SICURA"""
        if df.empty or len(df) < 5:
            LOG.warning("Troppi pochi dati per preparare features")
            return pd.DataFrame()

        features = pd.DataFrame()

        try:
            # 1. Features temporali semplici
            features['hour'] = df['hour'].astype(float)
            features['day_of_week'] = df['day_of_week'].astype(float)
            features['is_weekend'] = df['is_weekend'].astype(float)

            # 2. Features utente (encoding numerico semplice)
            # Mappa ogni utente a un numero
            unique_users = df['user'].unique()
            user_to_id = {user: idx for idx, user in enumerate(unique_users)}
            features['user_id'] = df['user'].map(user_to_id).astype(float)

            # 3. Features IP (solo primo ottetto)
            # Usa .loc per evitare SettingWithCopyWarning
            df_copy = df.copy()
            df_copy.loc[:, 'ip_first'] = df_copy['ip'].apply(
                lambda x: float(x.split('.')[0]) if '.' in x else 0.0
            )
            features['ip_first'] = df_copy['ip_first'].astype(float)

            # 4. Rate features (calcolate in modo sicuro)
            features['failure_rate'] = self._calculate_failure_rate_safe(df_copy)
            features['request_frequency'] = self._calculate_request_frequency_safe(df_copy)

            # 5. Features semplici aggiuntive
            features['is_failed'] = (df['event_type'] == 'auth_failed').astype(float)
            features['hour_sin'] = np.sin(2 * np.pi * features['hour'] / 24)
            features['hour_cos'] = np.cos(2 * np.pi * features['hour'] / 24)

            LOG.debug(f"Features create: {features.shape}")
            return features

        except Exception as e:
            LOG.error(f"Errore nella preparazione features: {e}")
            import traceback
            LOG.error(traceback.format_exc())
            return pd.DataFrame()

    def _calculate_failure_rate_safe(self, df: pd.DataFrame) -> pd.Series:
        """Calcola tasso di fallimento per utente - VERSIONE SICURA"""
        try:
            if 'event_type' not in df.columns:
                return pd.Series([0.0] * len(df))

            # Calcola per ogni utente
            user_stats = {}
            for user in df['user'].unique():
                user_mask = df['user'] == user
                user_events = df[user_mask]

                if len(user_events) == 0:
                    user_stats[user] = 0.0
                else:
                    failures = (user_events['event_type'] == 'auth_failed').sum()
                    user_stats[user] = failures / len(user_events)

            # Mappa a tutti gli eventi
            return df['user'].map(user_stats).fillna(0.0)

        except Exception as e:
            LOG.warning(f"Errore calcolo failure rate: {e}")
            return pd.Series([0.0] * len(df))

    def _calculate_request_frequency_safe(self, df: pd.DataFrame) -> pd.Series:
        """Calcola frequenza richieste - VERSIONE SICURA"""
        try:
            if len(df) == 0:
                return pd.Series([])

            # Frequenza semplice: eventi per utente negli ultimi 60 minuti
            frequencies = []
            df_sorted = df.sort_values('timestamp')

            for idx, row in df_sorted.iterrows():
                user = row['user']
                timestamp = row['timestamp']

                # Finestra di 60 minuti
                window_start = timestamp - timedelta(minutes=60)

                # Conta eventi per questo utente nella finestra
                mask = (df_sorted['user'] == user) & \
                       (df_sorted['timestamp'] >= window_start) & \
                       (df_sorted['timestamp'] <= timestamp)

                count = df_sorted[mask].shape[0]
                frequencies.append(count / 60.0)  # Eventi per minuto

            return pd.Series(frequencies, index=df_sorted.index).reindex(df.index).fillna(0.0)

        except Exception as e:
            LOG.warning(f"Errore calcolo frequenza: {e}")
            return pd.Series([0.0] * len(df))

    def train(self, df: pd.DataFrame):
        """Addestra il modello su dati storici - VERSIONE SICURA"""
        LOG.info(f"Addestramento modello su {len(df)} eventi...")

        if len(df) < 10:
            LOG.warning("Troppi pochi dati per l'addestramento. Richiesti almeno 10 eventi.")
            return

        try:
            # Prepara features
            features = self.prepare_features(df)

            if features.empty or len(features) < 10:
                LOG.warning("Features non sufficienti per l'addestramento")
                return

            # Salva profili utente (semplificati)
            for user in df['user'].unique():
                user_data = df[df['user'] == user]
                if len(user_data) > 0:
                    self.user_profiles[user] = {
                        'usual_ips': list(user_data['ip'].unique())[:5],  # Limita a 5 IP
                        'total_events': len(user_data),
                        'last_seen': user_data['timestamp'].max()
                    }

            # Addestra il modello
            features_array = features.values
            self.scaler.fit(features_array)
            features_scaled = self.scaler.transform(features_array)

            self.model.fit(features_scaled)
            LOG.info(f"✅ Modello addestrato su {len(features)} campioni")

        except Exception as e:
            LOG.error(f"Errore nell'addestramento: {e}")
            import traceback
            LOG.error(traceback.format_exc())

    def detect_anomalies(self, df: pd.DataFrame) -> pd.DataFrame:
        """Rileva anomalie in nuovi eventi - VERSIONE SICURA"""
        if df.empty:
            LOG.warning("DataFrame vuoto per la rilevazione")
            df['anomaly_score'] = 0.0
            df['is_anomaly'] = False
            return df

        LOG.info(f"Analisi di {len(df)} eventi...")

        try:
            # Prepara features
            features = self.prepare_features(df)

            if features.empty:
                LOG.warning("Nessuna feature estratta")
                df['anomaly_score'] = 0.0
                df['is_anomaly'] = False
                return df

            # Predici anomalie
            features_array = features.values
            features_scaled = self.scaler.transform(features_array)

            # Calcola score e predizioni
            anomaly_scores = self.model.decision_function(features_scaled)
            predictions = self.model.predict(features_scaled)

            # Aggiungi risultati al DataFrame
            df = df.copy()
            df['anomaly_score'] = anomaly_scores
            df['is_anomaly'] = predictions == -1

            # Aggiungi flag comportamentali
            df['unusual_ip'] = self._check_unusual_ip_safe(df)
            df['high_frequency'] = self._check_high_frequency_safe(df, threshold=0.2)

            # Statistiche
            anomaly_count = df['is_anomaly'].sum()
            LOG.info(f"✅ Analisi completata: {anomaly_count} anomalie rilevate")

            return df

        except Exception as e:
            LOG.error(f"Errore nella rilevazione anomalie: {e}")
            import traceback
            LOG.error(traceback.format_exc())

            # Fallback: segna tutto come normale
            df['anomaly_score'] = 0.0
            df['is_anomaly'] = False
            return df

    def _check_unusual_ip_safe(self, df: pd.DataFrame) -> pd.Series:
        """Controlla se IP è insolito per l'utente - VERSIONE SICURA"""
        results = []

        for idx, row in df.iterrows():
            user = row['user']
            ip = row['ip']

            if user in self.user_profiles:
                usual_ips = self.user_profiles[user].get('usual_ips', [])
                results.append(ip not in usual_ips)
            else:
                # Nuovo utente: non considerare insolito
                results.append(False)

        return pd.Series(results, index=df.index)

    def _check_high_frequency_safe(self, df: pd.DataFrame, threshold: float = 0.2) -> pd.Series:
        """Controlla frequenza eccessiva di tentativi - VERSIONE SICURA"""
        results = []
        df_sorted = df.sort_values('timestamp')

        for idx, row in df_sorted.iterrows():
            user = row['user']
            ip = row['ip']
            timestamp = row['timestamp']

            # Finestra di 5 minuti
            window_start = timestamp - timedelta(minutes=5)

            # Conta eventi per questa combinazione utente-IP
            mask = (df_sorted['user'] == user) & \
                   (df_sorted['ip'] == ip) & \
                   (df_sorted['timestamp'] >= window_start) & \
                   (df_sorted['timestamp'] <= timestamp)

            count = df_sorted[mask].shape[0]
            results.append(count > 5)  # Soglia: più di 3 a 5  tentativi in 5 minuti

        return pd.Series(results, index=df_sorted.index).reindex(df.index).fillna(False)

    def save_model(self, path: str):
        """Salva il modello addestrato"""
        try:
            with open(path, 'wb') as f:
                pickle.dump({
                    'model': self.model,
                    'scaler': self.scaler,
                    'user_profiles': dict(self.user_profiles)
                }, f)
            LOG.info(f"Modello salvato in {path}")
        except Exception as e:
            LOG.error(f"Errore nel salvataggio modello: {e}")

    def load_model(self, path: str):
        """Carica modello pre-addestrato"""
        try:
            with open(path, 'rb') as f:
                data = pickle.load(f)

            self.model = data['model']
            self.scaler = data['scaler']
            self.user_profiles = defaultdict(dict, data.get('user_profiles', {}))
            LOG.info(f"Modello caricato da {path}")
        except Exception as e:
            LOG.error(f"Errore nel caricamento modello: {e}")