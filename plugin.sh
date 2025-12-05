#!/bin/bash
# plugin.sh - DevStack plugin per AI Security Advisor

# Credenziali: dpr-auth-otf

function ai_security_advisor_install {
    echo_summary "Installing AI Security Advisor"

    # Crea directory
    sudo install -d -o $STACK_USER /opt/stack/ai-security-advisor
    sudo install -d -o $STACK_USER /opt/stack/ai-security-advisor/{models,logs,reports,config}

    # Copia i file del plugin dalla directory corrente
    cd /opt/stack/ai-security-advisor

    # Clona o copia i file
    if [ ! -d ".git" ]; then
        # Se stai sviluppando localmente, copia i file
        cp -r /path/to/your/local/ai-security-advisor/* /opt/stack/ai-security-advisor/ || true
    fi

    # Installa dipendenze Python
    pip_install pandas scikit-learn PyYAML watchdog
}

function ai_security_advisor_configure {
    echo_summary "Configuring AI Security Advisor"

    # Crea configurazione
    cat > /opt/stack/ai-security-advisor/config/devstack.yaml << EOF
log_path: "/opt/stack/logs/keystone.log"
model_path: "/opt/stack/ai-security-advisor/models/trained_model.pkl"

collector:
  type: "devstack"

whitelist:
  ips:
    - "127.0.0.1"
    - "172.24.4.1"

  users:
    - "nova"
    - "cinder"
    - "neutron"
    - "glance"
    - "heat"

keystone_api:
  enabled: false

debug:
  enabled: true
  log_level: "INFO"
EOF

    # Crea il modello iniziale vuoto se non esiste
    if [ ! -f "/opt/stack/ai-security-advisor/models/trained_model.pkl" ]; then
        echo "Creating initial empty model..."
        python3 -c "import pickle; pickle.dump({}, open('/opt/stack/ai-security-advisor/models/trained_model.pkl', 'wb'))"
    fi
}

function ai_security_advisor_start {
    echo_summary "Starting AI Security Advisor"

    # Avvia servizio in background
    run_process ai-security-advisor "cd /opt/stack/ai-security-advisor && \
        python3 main.py --realtime --config config/devstack.yaml"
}

function ai_security_advisor_stop {
    echo_summary "Stopping AI Security Advisor"
    stop_process ai-security-advisor
}

# Plugin dispatcher
if is_service_enabled ai-security-advisor; then
    case "$1" in
        stack)
            case "$2" in
                install)
                    ai_security_advisor_install
                    ;;
                post-config)
                    ai_security_advisor_configure
                    ;;
                extra)
                    ai_security_advisor_start
                    ;;
            esac
            ;;
        unstack)
            ai_security_advisor_stop
            ;;
        clean)
            # Opzionale: pulizia durante ./clean.sh
            ;;
    esac
fi