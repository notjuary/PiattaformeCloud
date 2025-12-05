import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict, Any
import logging

LOG = logging.getLogger(__name__)

class PolicyAdvisor:
    """Genera consigli di sicurezza basati sulle anomalie"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {
            'risk_threshold': 0.7,
            'mfa_threshold': 0.5,
            'block_threshold': 0.9,
            'cooldown_minutes': 30
        }

        self.action_history = []

    def analyze_event(self, event: pd.Series) -> List[Dict[str, Any]]:
        """Analizza un singolo evento e genera raccomandazioni - VERSIONE MIGLIORATA"""
        recommendations = []
        risk_score = event.get('anomaly_score', 0)

        # Normalizza score (IsolationForest: negativo = anomalia)
        # Più negativo = più anomalo
        normalized_score = abs(risk_score)  # Ora usiamo valore assoluto

        # Check 1: Tentativi multipli falliti
        if event.get('high_frequency', False) and not event.get('success', True):
            # Conta quanti tentativi falliti ci sono stati
            # (dovresti avere questa informazione nel DataFrame)
            recommendations.append({
                'action': 'temporary_block',
                'target': event['ip'],
                'duration_minutes': 30,
                'reason': f"Alta frequenza di tentativi falliti da {event['ip']}",
                'priority': 'high',
                'score': min(normalized_score + 0.3, 1.0)
            })

        # Check 2: IP insolito con fallimento
        if event.get('unusual_ip', False) and not event.get('success', True):
            recommendations.append({
                'action': 'force_mfa',
                'target': event['user'],
                'reason': f"Tentativo fallito da IP insolito {event['ip']}",
                'priority': 'medium',
                'score': min(normalized_score + 0.2, 1.0)
            })

        # Check 3: IP insolito con successo (potrebbe essere legittimo)
        if event.get('unusual_ip', False) and event.get('success', True):
            recommendations.append({
                'action': 'notify_user',
                'target': event['user'],
                'reason': f"Accesso riuscito da IP insolito {event['ip']}",
                'priority': 'low',
                'score': normalized_score
            })

        # Check 4: Anomalia generale ad alto rischio
        if event.get('is_anomaly', False) and normalized_score > self.config['risk_threshold']:
            recommendations.append({
                'action': 'review_session',
                'target': event['user'],
                'reason': f"Pattern di accesso anomalo (score: {normalized_score:.2f})",
                'priority': 'medium' if normalized_score < 0.8 else 'high',
                'score': normalized_score
            })

        return recommendations

    def _is_new_geolocation(self, event: pd.Series) -> bool:
        """Verifica se la geolocalizzazione è nuova per l'utente"""
        # Implementazione semplificata - in realtà usare API geolocation
        # Per ora controlla solo il prefisso di paese dall'IP
        ip_parts = event['ip'].split('.')
        country_prefix = f"{ip_parts[0]}.{ip_parts[1]}"

        # Dovresti avere un database storico delle localizzazioni
        # Qui ritorno sempre False per semplicità
        return False

    def _deduplicate_recommendations(self, recommendations: List[Dict]) -> List[Dict]:
        """Rimuove raccomandazioni duplicate"""
        seen = set()
        unique = []

        for rec in recommendations:
            key = f"{rec['action']}-{rec['target']}"
            if key not in seen:
                seen.add(key)
                unique.append(rec)

        # Ordina per score decrescente
        return sorted(unique, key=lambda x: x['score'], reverse=True)

    def generate_report(self, anomalies_df: pd.DataFrame) -> Dict[str, Any]:
        """Genera report giornaliero delle anomalie"""
        if len(anomalies_df) == 0:
            return {"status": "clean", "message": "Nessuna anomalia rilevata"}

        report = {
            "timestamp": datetime.now().isoformat(),
            "total_events": len(anomalies_df),
            "anomaly_count": anomalies_df['is_anomaly'].sum(),
            "high_risk_users": [],
            "suspicious_ips": [],
            "recommendations": []
        }

        # Utenti ad alto rischio
        high_risk_users = anomalies_df[anomalies_df['is_anomaly']].groupby('user').agg({
            'anomaly_score': 'mean',
            'ip': 'nunique'
        }).reset_index()

        for _, user in high_risk_users.iterrows():
            report['high_risk_users'].append({
                'user': user['user'],
                'avg_risk_score': float(user['anomaly_score']),
                'unique_ips': int(user['ip'])
            })

        # IP sospetti
        suspicious_ips = anomalies_df.groupby('ip').agg({
            'anomaly_score': 'mean',
            'user': 'nunique',
            'success': lambda x: (x == False).sum()
        }).reset_index()

        for _, ip in suspicious_ips.iterrows():
            report['suspicious_ips'].append({
                'ip': ip['ip'],
                'avg_risk_score': float(ip['anomaly_score']),
                'unique_users': int(ip['user']),
                'failed_attempts': int(ip['success'])
            })

        # Raccomandazioni aggregate
        all_recommendations = []
        for idx, event in anomalies_df.iterrows():
            recs = self.analyze_event(event)
            all_recommendations.extend(recs)

        report['recommendations'] = self._deduplicate_recommendations(all_recommendations)[:10]  # Top 10

        return report