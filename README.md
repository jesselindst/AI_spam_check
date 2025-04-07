# AI Spam Filter

This Python script monitors IMAP email accounts, analyzes incoming emails using the OpenAI GPT-4o-mini model, and moves suspected spam/phishing emails to a designated spam folder.

## Features

*   Connects to IMAP email accounts.
*   Continuously monitors the inbox for new emails.
*   Uses OpenAI's GPT-4o-mini API to analyze email content (subject, body, links, sender, CC, forwarded history) for signs of spam or phishing.
*   Moves identified spam emails to a specified spam folder.
*   Logs activity and errors for each account to separate files (e.g., `accountname_spam_filter.log`).
*   Processes multiple email accounts concurrently using multiprocessing.

## Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```
2.  **Install dependencies:**
    ```bash
    pip install requests imaplib
    ```
    *(Note: `email`, `time`, `configparser`, `logging`, `multiprocessing` are part of Python's standard library)*

3.  **Configure:**
    *   Copy the template configuration file:
        ```bash
        cp config.ini.template config.ini
        ```
    *   Edit `config.ini` with your details:
        *   `[EMAIL]`: Fill in your IMAP server host, email account username(s), password (use an app password if 2FA is enabled), and the exact name of your spam folder.
            *   For multiple accounts, add entries like `EMAIL_USER_ANOTHERACCOUNT=another@example.com`.
        *   `[OPENAI]`: Add your OpenAI API key.
    *   **Important:** Ensure `config.ini` is listed in your `.gitignore` file to avoid accidentally committing sensitive credentials.

## Usage

Run the script from your terminal:

```bash
python main.py
```

The script will start monitoring the configured email accounts. It will log its actions to the console and to account-specific log files (e.g., `jesse_spam_filter.log`).

Press `Ctrl+C` to stop the script gracefully.

## Security Note

*   Your email password and OpenAI API key are stored in `config.ini`. Protect this file carefully.
*   Consider using app-specific passwords for email accounts if your provider supports them, rather than your main account password.
