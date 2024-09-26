# SQLScanner
SQLScanner is a comprehensive Bash script designed for automated SQL injection testing. It enables security professionals and researchers to identify potential SQL injection vulnerabilities in web applications by leveraging an extensive list of payloads and logging capabilities.

# Key Features
Logging Logs SQL injection attempts and exploitation attempts into separate log files.
Extensive Payload List Includes a wide variety of SQL injection payloads for different testing scenarios.
Parallel Processing Uses GNU Parallel for scanning multiple URLs concurrently.
User Interaction Allows users to choose between scanning a list of URLs or a single URL.

# Usage 
Clone the repo
```bash
git clone https://github.com/SleepTheGod/SQLScanner
cd SQLScanner
```
Make the script executable
```bash
chmod +x main.sh
```
Execute and run the script
```bash
bash main.sh
```

# Requirements
Bash: Ensure you have a Bash-compatible shell.
GNU Parallel: Required for concurrent URL scanning. Install it using your package manager (e.g., sudo apt install parallel).
