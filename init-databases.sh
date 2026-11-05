
#!/usr/bin/env bash
# Initialize/reset vulnerable lab databases.
# WARNING: This resets existing lab data.
set -uo pipefail

DVWA=http://localhost:8090
BWAPP=http://localhost:8082
MUTILLIDAE=http://localhost:8083
FAILED=0

pass() { echo "[PASS] $1"; }
fail() { echo "[FAIL] $1"; FAILED=1; }

wait_for() {
  local url=$1 name=$2 i
  for i in $(seq 1 40); do
    if curl -s --max-time 5 -o /dev/null "$url"; then
      return 0
    fi
    sleep 3
  done
  fail "$name did not respond at $url"
  return 1
}

echo "Initializing DVWA..."
if wait_for "$DVWA/setup.php" DVWA; then
  jar=$(mktemp)
  token=$(curl -s -c "$jar" "$DVWA/setup.php" |
    grep -oE '[a-f0-9]{32}' | head -1)

  curl -s -b "$jar" -c "$jar" \
    -X POST "$DVWA/setup.php" \
    --data-urlencode 'create_db=Create / Reset Database' \
    --data-urlencode "user_token=$token" >/dev/null

  rm -f "$jar"

  n=$(docker exec lab-dvwa \
    mysql -uroot -pp@ssw0rd -N -B \
    -e 'SELECT COUNT(*) FROM dvwa.users;' \
    2>/dev/null | tail -1)

  if [[ "$n" =~ ^[0-9]+$ ]] && (( n > 0 )); then
    pass "DVWA database initialized"
  else
    fail "DVWA database initialization failed"
  fi
fi

echo "Initializing bWAPP..."
if wait_for "$BWAPP/install.php" bWAPP; then
  curl -s "$BWAPP/install.php?install=yes" >/dev/null

  n=$(docker exec lab-bwapp \
    mysql -uroot -N -B \
    -e 'SELECT COUNT(*) FROM bWAPP.users;' \
    2>/dev/null | tail -1)

  if [[ "$n" =~ ^[0-9]+$ ]] && (( n > 0 )); then
    pass "bWAPP database initialized"
  else
    fail "bWAPP database initialization failed"
  fi
fi

echo "Initializing Mutillidae..."
if wait_for "$MUTILLIDAE/set-up-database.php" Mutillidae; then
  curl -s "$MUTILLIDAE/set-up-database.php" >/dev/null

  n=$(docker exec lab-mutillidae \
    mysql -uroot -N -B \
    -e 'SELECT COUNT(*) FROM mutillidae.accounts;' \
    2>/dev/null | tail -1)

  if [[ "$n" =~ ^[0-9]+$ ]] && (( n > 0 )); then
    pass "Mutillidae database initialized"
  else
    fail "Mutillidae database initialization failed"
  fi
fi

if (( FAILED == 0 )); then
  echo "All databases initialized."
else
  echo "Some databases failed."
  exit 1
fi
