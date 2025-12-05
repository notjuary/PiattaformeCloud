#!/bin/bash
# test_on_devstack.sh
# Script da eseguire SULLA VM Ubuntu con DevStack

set -e

echo "🧪 AI Security Advisor - Test su DevStack"
echo "========================================="

# Directory
AI_DIR="/opt/stack/ai-security-advisor"
cd $AI_DIR

# 1. Attiva virtualenv
if [ -d "venv" ]; then
    source venv/bin/activate
fi

# 2. Carica ambiente DevStack
if [ -f "/opt/stack/openrc" ]; then
    source /opt/stack/openrc admin admin
    echo "✅ Ambiente DevStack caricato"
else
    echo "⚠️  Ambiente DevStack non trovato"
fi

# 3. Verifica log Keystone
KEYSTONE_LOG="/opt/stack/logs/keystone.log"
if [ -f "$KEYSTONE_LOG" ]; then
    LOG_SIZE=$(du -h "$KEYSTONE_LOG" | cut -f1)
    LOG_LINES=$(wc -l < "$KEYSTONE_LOG")
    echo "✅ Log Keystone: $LOG_SIZE, $LOG_LINES righe"
else
    echo "❌ Log Keystone non trovato: $KEYSTONE_LOG"
    echo "   Cerca log alternativi..."
    find /opt/stack/logs -name "*keystone*" -type f 2>/dev/null | head -5
fi

# 4. Genera traffico di test
echo ""
echo "🚀 Generazione traffico di test..."
echo "   (Questo aggiungerà eventi al log per testare l'analisi)"
echo ""

# Comandi che generano eventi di autenticazione
COMMANDS=(
    "openstack token issue"
    "openstack user list --limit 3"
    "openstack project list --limit 3"
    "openstack --os-password wrongpass token issue 2>&1 | grep -v '^$'"
    "openstack --os-username wronguser token issue 2>&1 | grep -v '^$'"
)

for cmd in "${COMMANDS[@]}"; do
    echo "   Eseguendo: $cmd"
    eval $cmd > /dev/null 2>&1 || true
    sleep 1
done

# 5. Test del collector
echo ""
echo "🔍 Test del collector..."
python -c "
import sys
sys.path.insert(0, '.')
from ai_security_advisor.collector import KeystoneLogCollector

collector = KeystoneLogCollector('/opt/stack/logs/keystone.log')
events = collector.collect_historical_events(hours=0.5)  # Ultime 30 minuti

print(f'Eventi raccolti: {len(events)}')
if len(events) > 0:
    print('\\nUltimi 5 eventi:')
    print(events[['timestamp', 'user', 'ip', 'event_type']].tail())
else:
    print('⚠️  Nessun evento trovato')
    print('💡 Verifica che il formato del log sia corretto')
"

# 6. Test completo dell'advisor
echo ""
echo "🤖 Test completo AI Security Advisor..."
python main.py --analyze --hours 1 --config config/devstack.yaml

echo ""
echo "========================================="
echo "✅ Test completato!"
echo ""
echo "📋 Prossimi passi:"
echo "1. Per monitoraggio continuo:"
echo "   python main.py --realtime --config config/devstack.yaml"
echo ""
echo "2. Per addestrare su dati storici:"
echo "   python main.py --train --config config/devstack.yaml"
echo ""
echo "3. Log dell'applicazione:"
echo "   tail -f $AI_DIR/logs/ai_security.log"
echo ""
echo "4. Report generati:"
echo "   ls -la $AI_DIR/reports/"