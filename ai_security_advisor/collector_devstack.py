"""
Collector specifico per DevStack Keystone logs
"""
import re
from .collector import BaseLogCollector
import logging

LOG = logging.getLogger(__name__)


class DevStackKeystoneCollector(BaseLogCollector):
    """Collector per log Keystone di DevStack"""

    def _get_patterns(self):
        """Pattern specifici per DevStack"""
        return [
            # Pattern 1: Autenticazione riuscita
            r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+).*INFO.*Authenticated user\[(?P<user>[^\]]+)\]',

            # Pattern 2: Autenticazione fallita
            r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+).*ERROR.*Authorization failed.*user\[(?P<user>[^\]]+)\]',

            # Pattern 3: Token creato
            r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+).*INFO.*Created token.*user\[(?P<user>[^\]]+)\]',

            # Pattern 4: Richiesta HTTP con IP
            r'(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+).*\[req-[^]]+\].*(?P<method>GET|POST|PUT|DELETE).*"(?P<url>[^"]+)".*(?P<status>\d{3}).*from (?P<ip>\d+\.\d+\.\d+\.\d+)',
        ]

    def _classify_event(self, event: Dict, line: str):
        """Classifica eventi DevStack"""
        if 'Authorization failed' in line or 'Invalid authentication' in line:
            event['event_type'] = 'auth_failed'
            event['success'] = False
        elif 'Authenticated user' in line or 'Created token' in line:
            event['event_type'] = 'auth_success'
            event['success'] = True
        elif 'POST /v3/auth/tokens' in line:
            status = event.get('status', '200')
            if status in ['200', '201']:
                event['event_type'] = 'auth_success'
                event['success'] = True
            else:
                event['event_type'] = 'auth_failed'
                event['success'] = False

    def _enrich_event(self, event: Dict):
        """Aggiunge info specifiche DevStack"""
        super()._enrich_event(event)

        # Flag per IP interni DevStack
        devstack_ips = ['172.24.4.1', '127.0.0.1', '10.0.0.0/8', '192.168.0.0/16']
        event['is_internal_ip'] = any(
            self._ip_in_network(event.get('ip', ''), network)
            for network in devstack_ips
        )

    def _ip_in_network(self, ip: str, network: str) -> bool:
        """Controlla se IP è nella rete"""
        if '/' not in network:
            return ip == network

        # Implementazione semplificata
        ip_parts = list(map(int, ip.split('.')))
        net_addr, prefix = network.split('/')
        net_parts = list(map(int, net_addr.split('.')))
        prefix = int(prefix)

        # Calcola maschera
        mask = (0xffffffff << (32 - prefix)) & 0xffffffff

        # Confronta
        ip_num = (ip_parts[0] << 24) + (ip_parts[1] << 16) + (ip_parts[2] << 8) + ip_parts[3]
        net_num = (net_parts[0] << 24) + (net_parts[1] << 16) + (net_parts[2] << 8) + net_parts[3]

        return (ip_num & mask) == (net_num & mask)