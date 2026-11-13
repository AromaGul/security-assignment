#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

echo "=== Assignment 1: Docker Lab Database Initialization ==="

# Ensure containers are running
docker compose ps

wait_for_url() {
    local url="$1"
    local name="$2"

    echo "Waiting for $name..."

    for i in $(seq 1 30); do
        if curl -fsS --max-time 5 -o /dev/null "$url"; then
            return 0
        fi
        sleep 2
    done

    echo "ERROR: $name is not responding."
    return 1
}

# DVWA
wait_for_url "http://127.0.0.1:8090/setup.php" "DVWA"

if docker exec lab-dvwa php -r '
require "/var/www/html/config/config.inc.php";
$db = new mysqli(
    $_DVWA["db_server"],
    $_DVWA["db_user"],
    $_DVWA["db_password"],
    $_DVWA["db_database"]
);
$result = $db->query("SHOW TABLES");
$tables = [];
while ($row = $result->fetch_row()) {
    $tables[] = $row[0];
}
exit(in_array("users", $tables) && in_array("guestbook", $tables) ? 0 : 1);
'; then
    echo "[OK] DVWA already initialized."
else
    echo "[INFO] Initializing DVWA..."

    # Obtain the session cookie and CSRF token
    cookie_file=$(mktemp)
    trap 'rm -f "$cookie_file"' EXIT

    page=$(curl -fsS -c "$cookie_file" \
        "http://127.0.0.1:8090/setup.php")

    token=$(printf '%s' "$page" |
        grep -oP "name=['\"]user_token['\"] value=['\"]\K[^'\"]+" |
        head -1 || true)

    if [[ -z "$token" ]]; then
        echo "ERROR: DVWA setup token not found."
        exit 1
    fi

    curl -fsS -b "$cookie_file" -c "$cookie_file" \
        --data-urlencode "create_db=Create / Reset Database" \
        --data-urlencode "user_token=$token" \
        "http://127.0.0.1:8090/setup.php" >/dev/null

    echo "[OK] DVWA initialization request completed."
fi

# bWAPP
wait_for_url "http://127.0.0.1:8082/install.php" "bWAPP"

if docker exec lab-bwapp mysql -u root -N -e \
    "SHOW TABLES FROM bWAPP;" 2>/dev/null |
    grep -qx "users"; then
    echo "[OK] bWAPP already initialized."
else
    echo "[INFO] Initializing bWAPP..."

    curl -fsS \
        "http://127.0.0.1:8082/install.php?install=yes" \
        >/dev/null

    echo "[OK] bWAPP initialization request completed."
fi

# Mutillidae
wait_for_url "http://127.0.0.1:8083/index.php" "Mutillidae"

if docker exec lab-mutillidae php -r '
require "/app/includes/database-config.php";
require "/app/classes/MySQLHandler.php";
$db = new mysqli(
    DB_HOST,
    MySQLHandler::$mMySQLDatabaseUsername,
    MySQLHandler::$mMySQLDatabasePassword,
    DB_NAME
);
$result = $db->query("SHOW TABLES");
$tables = [];
while ($row = $result->fetch_row()) {
    $tables[] = $row[0];
}
exit(in_array("blogs_table", $tables) && in_array("accounts", $tables) ? 0 : 1);
'; then
    echo "[OK] Mutillidae already initialized."
else
    echo "[INFO] Initializing Mutillidae..."

    # WARNING: This endpoint drops and recreates its database.
    # Only invoke when the expected tables are absent.
    curl -fsS \
        "http://127.0.0.1:8083/set-up-database.php" \
        >/dev/null

    echo "[OK] Mutillidae initialization request completed."
fi

echo
echo "=== Initialization process finished ==="
echo "DVWA:       http://127.0.0.1:8090"
echo "bWAPP:      http://127.0.0.1:8082"
echo "Mutillidae: http://127.0.0.1:8083"
