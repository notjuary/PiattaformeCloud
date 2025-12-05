#!/bin/bash
# Script di installazione per la VM Ubuntu con DevStack

set -e

echo "🔧 Installazione AI Security Advisor su VM"
echo "=========================================="

# 1. Aggiorna sistema
echo "📦 Aggiornamento sistema..."
sudo apt update
sudo apt upgrade -y

# 2. Installa dipendenze Python
echo "🐍 Installazione dipendenze Python..."
sudo apt install -y python3-pip python3-venv python3-dev

# 3. Clona repository
echo "📥 Cloning repository..."
cd /opt/stack
if [ ! -d "ai-security-advisor" ]; then
    git clone https://github.com/notjuary/PiattaformeCloud.git ai-security-advisor
fi

cd ai-security-advisor

# 4. Crea virtualenv
echo "🔧 Creazione virtual environment..."
python3 -m venv venv
source venv/bin/activate

# 5. Installa dipendenze
echo "📦 Installazione dipendenze Python..."
pip install --upgrade pip
pip install pandas scikit-learn PyYAML python-keystoneclient

# 6. Crea directory necessarie
echo "📁 Creazione directory..."
mkdir -p logs models reports

# 7. Crea configurazione per DevStack
echo "⚙️  Creazione configurazione..."
cat > config/devstack_vm.yaml << 'EOF'
# Configurazione per DevStack su VM
log_path: "/opt/stack/logs/keystone.log"
model_path: "models/devstack_vm_model.pkl"

collector:
  type: "devstack"
  max_lines_per_scan: 50000

ai_engine:
  n_estimators: 100
  contamination: 0.05
  max_samples: "auto"
  random_state: 42

policy:
  risk_threshold: 0.7
  high_risk_threshold: 0.85
  max_failed_attempts: 5

whitelist:
  ips:
    - "127.0.0.1"
    - "172.24.4.1"
    - "10.0.0.0/8"

  users:
    - "nova"
    - "cinder"
    - "neutron"
    - "glance"
    - "heat"

debug:
  enabled: true
  log_level: "INFO"
EOF

# 8. Test iniziale
echo "🧪 Test iniziale..."
python -c "
import sys
sys.path.insert(0, '.')
from ai_security_advisor.collector import KeystoneLogCollector

collector = KeystoneLogCollector('/opt/stack/logs/keystone.log')
events = collector.collect_historical_events(1)
print(f'Eventi trovati: {len(events)}')
"

# 9. Crea script di avvio
echo "🚀 Creazione script di avvio..."
cat > start_advisor.sh << 'EOF'
#!/bin/bash
cd /opt/stack/ai-security-advisor
source venv/bin/activate
python main.py --realtime --config config/devstack_vm.yaml
EOF

chmod +x start_advisor.sh

# 10. Crea service systemd
echo "🔄 Creazione service systemd..."
sudo tee /etc/systemd/system/ai-security-advisor.service > /dev/null << EOF
[Unit]
Description=AI Security Advisor for OpenStack
After=devstack@keystone.service
Requires=devstack@keystone.service

[Service]
Type=simple
User=stack
WorkingDirectory=/opt/stack/ai-security-advisor
Environment=PATH=/opt/stack/ai-security-advisor/venv/bin:/usr/local/bin:/usr/bin:/bin
ExecStart=/opt/stack/ai-security-advisor/start_advisor.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

echo ""
echo "✅ Installazione completata!"
echo ""
echo "📋 Comandi utili:"
echo "   Avvia manualmente:  ./start_advisor.sh"
echo "   Avvia con systemd:  sudo systemctl start ai-security-advisor"
echo "   Abilita all'avvio:  sudo systemctl enable ai-security-advisor"
echo "   Visualizza log:     journalctl -u ai-security-advisor -f"
echo ""
echo "🧪 Per testare:"
echo "   cd /opt/stack/ai-security-advisor"
echo "   python scripts/test_with_real_data.py"