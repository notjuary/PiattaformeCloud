#!/bin/bash
# deploy_to_devstack.sh
# Script per deploy su VM Ubuntu con DevStack

set -e

echo "🚀 Deploy AI Security Advisor su DevStack"
echo "=========================================="

# Variabili
VM_USER="ubuntu"                     # Modifica con il tuo utente VM
VM_IP="192.168.1.X"                  # Modifica con IP della VM
DEVSTACK_DIR="/opt/stack"
AI_DIR="$DEVSTACK_DIR/ai-security-advisor"
LOCAL_PROJECT_DIR="$(pwd)"

# 1. Verifica connessione alla VM
echo "1. 📡 Verifica connessione alla VM..."
ping -c 1 $VM_IP > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "❌ VM non raggiungibile: $VM_IP"
    echo "   Verifica:"
    echo "   - La VM è accesa?"
    echo "   - IP corretto?"
    echo "   - Connessione di rete?"
    exit 1
fi
echo "   ✅ VM raggiungibile"

# 2. Crea directory sulla VM
echo "2. 📁 Creazione directory sulla VM..."
ssh $VM_USER@$VM_IP "sudo mkdir -p $AI_DIR && sudo chown -R $USER:$USER $AI_DIR"

# 3. Copia i file sulla VM
echo "3. 📦 Copia file sulla VM..."
scp -r \
    $LOCAL_PROJECT_DIR/ai_security_advisor \
    $LOCAL_PROJECT_DIR/config \
    $LOCAL_PROJECT_DIR/scripts \
    $LOCAL_PROJECT_DIR/main.py \
    $LOCAL_PROJECT_DIR/requirements.txt \
    $LOCAL_PROJECT_DIR/plugin.sh \
    $VM_USER@$VM_IP:$AI_DIR/

# 4. Installa dipendenze sulla VM
echo "4. 🐍 Installazione dipendenze Python..."
ssh $VM_USER@$VM_IP << 'EOF'
cd /opt/stack/ai-security-advisor

# Crea virtualenv
if [ ! -d "venv" ]; then
    python3 -m venv venv
fi

source venv/bin/activate
pip install --upgrade pip
pip install pandas scikit-learn PyYAML watchdog python-keystoneclient keystoneauth1
EOF

# 5. Crea configurazione DevStack
echo "5. ⚙️  Configurazione per DevStack..."
ssh $VM_USER@$VM_IP "cat > $AI_DIR/config/devstack.yaml << 'EOF'
# Configurazione per DevStack
log_path: \"/opt/stack/logs/keystone.log\"
model_path: \"$AI_DIR/models/devstack_model.pkl\"
database_path: \"$AI_DIR/security_events.db\"

collector:
  type: \"devstack\"
  max_lines_per_scan: 10000

ai_engine:
  n_estimators: 50
  contamination: 0.01
  max_features: 0.5
  bootstrap: true
  training_hours: 24

policy:
  risk_threshold: 0.7
  mfa_threshold: 0.5
  block_threshold: 0.9
  max_failed_attempts: 5

whitelist:
  ips:
    - \"127.0.0.1\"
    - \"172.24.4.1\"
    - \"10.0.0.0/8\"

  users:
    - \"nova\"
    - \"cinder\"
    - \"neutron\"
    - \"glance\"
    - \"heat\"
    - \"admin\"

keystone_api:
  enabled: false
  auth_url: \"http://172.24.4.1:5000/v3\"
  username: \"admin\"
  password: \"secret\"  # Cambia con la password reale
  project_name: \"admin\"

notifications:
  console:
    enabled: true
    level: \"INFO\"

  file:
    enabled: true
    path: \"$AI_DIR/logs/ai_security.log\"

debug:
  enabled: true
  log_level: \"INFO\"
EOF"

# 6. Test rapido sulla VM
echo "6. 🧪 Test rapido sulla VM..."
ssh $VM_USER@$VM_IP << 'EOF'
cd /opt/stack/ai-security-advisor
source venv/bin/activate

echo "Test 1: Verifica DevStack..."
if [ -f "/opt/stack/openrc" ]; then
    source /opt/stack/openrc admin admin
    echo "✅ DevStack trovato"
else
    echo "⚠️  DevStack non trovato in /opt/stack"
fi

echo "Test 2: Verifica log Keystone..."
if [ -f "/opt/stack/logs/keystone.log" ]; then
    LOG_SIZE=$(du -h "/opt/stack/logs/keystone.log" | cut -f1)
    echo "✅ Log Keystone trovato: $LOG_SIZE"
else
    echo "❌ Log Keystone non trovato"
fi

echo "Test 3: Import moduli Python..."
python -c "
import sys
sys.path.insert(0, '.')
from ai_security_advisor.collector import KeystoneLogCollector
from ai_security_advisor.ai_engine import AnomalyDetector
print('✅ Import riuscito')
"
EOF

echo ""
echo "=========================================="
echo "✅ DEPLOY COMPLETATO!"
echo "=========================================="
echo ""
echo "📋 Comandi per testare sulla VM:"
echo ""
echo "1. Connettiti alla VM:"
echo "   ssh $VM_USER@$VM_IP"
echo ""
echo "2. Vai alla directory:"
echo "   cd $AI_DIR"
echo ""
echo "3. Attiva virtualenv:"
echo "   source venv/bin/activate"
echo ""
echo "4. Testa il collector:"
echo "   python -c \""
echo "   import sys"
echo "   sys.path.insert(0, '.')"
echo "   from ai_security_advisor.collector import KeystoneLogCollector"
echo "   collector = KeystoneLogCollector('/opt/stack/logs/keystone.log')"
echo "   events = collector.collect_historical_events(1)"
echo "   print(f'Eventi: {len(events)}')"
echo "   \""
echo ""
echo "5. Esegui analisi completa:"
echo "   python main.py --analyze --hours 2 --config config/devstack.yaml"
echo ""
echo "6. Genera traffico di test (in un altro terminale):"
echo "   source /opt/stack/openrc admin admin"
echo "   openstack token issue"
echo "   openstack --os-password wrongpass token issue 2>/dev/null"