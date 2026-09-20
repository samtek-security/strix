#!/bin/bash
# Modified by Samtek for Recon. Derived from Apache-2.0 Strix (OmniSecure Inc.). See NOTICE.
set -e

CAIDO_PORT=48080
CAIDO_LOG="/tmp/caido_startup.log"

if [ ! -f /app/certs/ca.p12 ]; then
  echo "ERROR: CA certificate file /app/certs/ca.p12 not found."
  exit 1
fi

caido-cli --listen 0.0.0.0:${CAIDO_PORT} \
          --allow-guests \
          --no-logging \
          --no-open \
          --import-ca-cert /app/certs/ca.p12 \
          --import-ca-cert-pass "" > "$CAIDO_LOG" 2>&1 &

CAIDO_PID=$!
echo "Started Caido with PID $CAIDO_PID on port $CAIDO_PORT"

echo "Waiting for Caido API to be ready..."
CAIDO_READY=false
for i in {1..30}; do
  if ! kill -0 $CAIDO_PID 2>/dev/null; then
    echo "ERROR: Caido process died while waiting for API (iteration $i)."
    echo "=== Caido log ==="
    cat "$CAIDO_LOG" 2>/dev/null || echo "(no log available)"
    exit 1
  fi

  if curl -s -o /dev/null -w "%{http_code}" http://localhost:${CAIDO_PORT}/graphql/ | grep -qE "^(200|400)$"; then
    echo "Caido API is ready (attempt $i)."
    CAIDO_READY=true
    break
  fi
  sleep 1
done

if [ "$CAIDO_READY" = false ]; then
  echo "ERROR: Caido API did not become ready within 30 seconds."
  echo "Caido process status: $(kill -0 $CAIDO_PID 2>&1 && echo 'running' || echo 'dead')"
  echo "=== Caido log ==="
  cat "$CAIDO_LOG" 2>/dev/null || echo "(no log available)"
  exit 1
fi

sleep 2

echo "Caido is up — host bootstraps the guest token + project via the Python SDK."

# CONTAINED egress (P0-2, docs/SPEC-sandbox-containment.md): when RECON_EGRESS_UPSTREAM is set, the
# sandbox is sealed on an internal-only network and its ONLY egress is the trusted gateway. Point the
# system proxy AND the browser at the gateway instead of the in-container Caido (which would dial the
# target directly and has no route on a sealed network). Capture happens at the gateway (mitmproxy,
# A2). Unset => stock behaviour (proxy through the in-container Caido).
if [ -n "${RECON_EGRESS_UPSTREAM:-}" ]; then
  GATEWAY_CA=/recon-ca/recon-egress-ca.pem
  if [ ! -s "$GATEWAY_CA" ]; then
    echo "ERROR: contained egress gateway CA is missing; refusing to start."
    exit 1
  fi
  sudo cp "$GATEWAY_CA" /usr/local/share/ca-certificates/recon-egress-ca.crt
  sudo update-ca-certificates >/dev/null
  PROXY_URL="${RECON_EGRESS_UPSTREAM}"
  echo "recon: CONTAINED egress -> routing the sandbox through the gateway ${PROXY_URL} (Caido bypassed)"
else
  PROXY_URL="http://127.0.0.1:${CAIDO_PORT}"
fi

echo "Configuring system-wide proxy settings..."

cat << EOF | sudo tee /etc/profile.d/proxy.sh
export http_proxy=${PROXY_URL}
export https_proxy=${PROXY_URL}
export HTTP_PROXY=${PROXY_URL}
export HTTPS_PROXY=${PROXY_URL}
export ALL_PROXY=${PROXY_URL}
export NO_PROXY=localhost,127.0.0.1
export REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt
export SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
EOF

cat << EOF | sudo tee /etc/environment
http_proxy=${PROXY_URL}
https_proxy=${PROXY_URL}
HTTP_PROXY=${PROXY_URL}
HTTPS_PROXY=${PROXY_URL}
ALL_PROXY=${PROXY_URL}
NO_PROXY=localhost,127.0.0.1
EOF

cat << EOF | sudo tee /etc/wgetrc
use_proxy=yes
http_proxy=${PROXY_URL}
https_proxy=${PROXY_URL}
EOF

# agent-browser (Chromium) ignores http_proxy env, so in contained mode pass the gateway explicitly
# via --proxy-server (comma-appended to the existing browser args). Written to /etc/environment +
# profile.d so it reaches the browser however it is launched.
if [ -n "${RECON_EGRESS_UPSTREAM:-}" ]; then
  BROWSER_ARGS="${AGENT_BROWSER_ARGS:+${AGENT_BROWSER_ARGS},}--proxy-server=${PROXY_URL}"
  echo "export AGENT_BROWSER_ARGS=\"${BROWSER_ARGS}\"" | sudo tee -a /etc/profile.d/proxy.sh >/dev/null
  echo "AGENT_BROWSER_ARGS=${BROWSER_ARGS}" | sudo tee -a /etc/environment >/dev/null
  export AGENT_BROWSER_ARGS="${BROWSER_ARGS}"
  echo "recon: browser proxy-server -> ${PROXY_URL}"
fi

echo "source /etc/profile.d/proxy.sh" >> ~/.bashrc
echo "source /etc/profile.d/proxy.sh" >> ~/.zshrc

source /etc/profile.d/proxy.sh

echo "✅ System-wide proxy configuration complete"

echo "Adding CA to browser trust store..."
sudo -u pentester mkdir -p /home/pentester/.pki/nssdb
sudo -u pentester certutil -N -d sql:/home/pentester/.pki/nssdb --empty-password
sudo -u pentester certutil -A -n "Testing Root CA" -t "C,," -i /app/certs/ca.crt -d sql:/home/pentester/.pki/nssdb
if [ -n "${RECON_EGRESS_UPSTREAM:-}" ]; then
  sudo -u pentester certutil -A -n "Recon Egress Gateway CA" -t "C,," \
    -i /recon-ca/recon-egress-ca.pem -d sql:/home/pentester/.pki/nssdb
fi
echo "✅ CA added to browser trust store"

mkdir -p /workspace/.agent-browser-screenshots

touch /tmp/recon-agent-ready
echo "✅ Container ready"

cd /workspace
exec "$@"
