"""
Client per interagire con Keystone API
"""
import logging
from typing import Optional, Dict, Any

LOG = logging.getLogger(__name__)

class KeystoneAPIClient:
    """Client per eseguire azioni su Keystone"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.client = None

        if config.get('enabled', False):
            self._initialize_client()

    def _initialize_client(self):
        """Inizializza il client Keystone"""
        try:
            # Importa qui per non richiedere keystoneclient se non necessario
            from keystoneauth1.identity import v3
            from keystoneauth1 import session
            from keystoneclient.v3 import client as keystone_client

            auth = v3.Password(
                auth_url=self.config['auth_url'],
                username=self.config['username'],
                password=self.config['password'],
                project_name=self.config['project_name'],
                user_domain_name=self.config.get('user_domain_name', 'Default'),
                project_domain_name=self.config.get('project_domain_name', 'Default')
            )

            sess = session.Session(auth=auth)
            self.client = keystone_client.Client(session=sess)

            LOG.info("Keystone client inizializzato")

        except ImportError:
            LOG.warning("python-keystoneclient non installato. Usa: pip install python-keystoneclient")
        except Exception as e:
            LOG.error(f"Errore inizializzazione Keystone client: {e}")

    def is_available(self) -> bool:
        """Verifica se il client è disponibile"""
        return self.client is not None

    def test_connection(self) -> bool:
        """Testa la connessione a Keystone"""
        if not self.is_available():
            return False

        try:
            # Prova a ottenere un token
            self.client.tokens.validate()
            return True
        except Exception as e:
            LOG.error(f"Test connessione fallito: {e}")
            return False