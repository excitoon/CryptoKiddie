#!/usr/bin/env bash
# Continuously service the CryptoKiddie bridge queue for the ESIA Safari tab.
# Drains window.__cryptokiddieBridgeQueue.requests and posts them to the local
# bridge, delivering responses back into the page.
set -u
cd "$(dirname "$0")"
export CRYPTOKIDDIE_GOSUSLUGI_TAB_URL="${CRYPTOKIDDIE_GOSUSLUGI_TAB_URL:-esia.gosuslugi.ru}"
export CRYPTOKIDDIE_GOSUSLUGI_BRIDGE_URL="${CRYPTOKIDDIE_GOSUSLUGI_BRIDGE_URL:-http://127.0.0.1:18765}"
echo "esia pump loop: tab=$CRYPTOKIDDIE_GOSUSLUGI_TAB_URL bridge=$CRYPTOKIDDIE_GOSUSLUGI_BRIDGE_URL"
while true; do
  out="$(ruby ./gosuslugi-safari-pump-once.rb 2>&1)"
  if echo "$out" | grep -qv 'requests=0'; then
    echo "$out" | grep -v 'requests=0'
  fi
  sleep 0.4
done
