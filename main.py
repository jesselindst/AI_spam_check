import imaplib
import email
import time
import requests
import configparser
import logging
from email.header import decode_header
from multiprocessing import Process

# Load configuration
config = configparser.ConfigParser()
config.read('config.ini')

imap_host = config['EMAIL']['IMAP_HOST']
email_accounts = {
    "jesse": config['EMAIL']['EMAIL_USER_JESSE'],

}
email_pass = config['EMAIL']['EMAIL_PASS']
api_key = config['OPENAI']['API_KEY']
spam_folder = config['EMAIL']['SPAM_FOLDER']


def configure_logging(account_name):
    """Configure logging for a specific email account."""
    logger = logging.getLogger(account_name)
    logger.setLevel(logging.INFO)
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

    file_handler = logging.FileHandler(f"{account_name}_spam_filter.log")
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    return logger


def extract_text_content(msg):
    """Extract text content, links, sender, CC, and forwarded history from an email message."""
    body = ""
    links = []
    forwarded_history = []

    # Extract sender and CC
    sender = msg.get("From", "Unknown Sender")
    cc = msg.get("Cc", "No CC")

    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body_part = part.get_payload(
                    decode=True).decode(errors="ignore")
                body += body_part
            elif part.get_content_type() == "message/rfc822":
                forwarded_part = part.get_payload(
                    decode=True).decode(errors="ignore")
                forwarded_history.append(forwarded_part)
    else:
        if msg.get_content_type() == "text/plain":
            body = msg.get_payload(decode=True).decode(errors="ignore")

    # Extract links from the plain text body
    for line in body.splitlines():
        if "http://" in line or "https://" in line:
            links.append(line.strip())

    return body, links, sender, cc, "\n".join(forwarded_history)


def is_spam_via_gpt(subject, body, links, sender, cc, forwarded_history, logger):
    """
    Check if an email is spam using GPT-4 API.
    """
    api_url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    print(subject, body, links, sender, cc, forwarded_history)

    data = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": "Analyze an email and determine if it is fraudulent. Reply only with True or False."},
            {"role": "system",
             "content": "Verify the sender and any original sender in forwarded emails (e.g., PayPal must not be paypal@email.cz)."},
            {"role": "system",
             "content": "Not all Invoices are spam, the senders email address is a good indication for the legitimacy."},
            {"role": "system",
             "content": "Check if links are legitimate."},
            {"role": "system",
             "content": "Flag suspicious attachments (e.g., executables, scripts) and threatening or urgent language."},
            {"role": "system",
             "content": "Identify phishing signs like generic greetings, requests for personal data, or inconsistencies (e.g., dead links)."},
            {"role": "system", "content": "Analyze fully and respond with True if fraudulent, otherwise False."},
            {"role": "user", "content": f"Subject: {subject}\nBody: {body}\nLinks: {', '.join(links)}\nSender: {sender}\nCC: {cc}\nForwarded History: {forwarded_history}\nIs this email spam? Reply only with True or False."}
        ]
    }

    try:
        response = requests.post(
            api_url, headers=headers, json=data, timeout=10)
        response.raise_for_status()
        result = response.json()
        reply = result['choices'][0]['message']['content'].strip()
        return reply == "True"
    except requests.exceptions.RequestException as e:
        logger.error(f"Failed to check spam via GPT-4 API: {e}")
        return False


def process_email_account(account_name, email_user):
    """Process emails for a specific account."""
    logger = configure_logging(account_name)
    logger.info(f"Starting spam filter for {account_name}")

    try:
        mail = imaplib.IMAP4_SSL(imap_host)
        mail.login(email_user, email_pass)
        logger.info(f"Connected to IMAP server for {account_name}")
    except Exception as e:
        logger.critical(f"Failed to connect to IMAP server for {
                        account_name}: {e}")
        return

    try:
        mail.select('inbox')
        status, data = mail.uid('SEARCH', None, 'ALL')
        initial_uids = data[0].split()
        last_uid = int(initial_uids[-1]) if initial_uids else 0
        processed_uids = set()
        logger.info(f"Script started for {
                    account_name}. Last known UID: {last_uid}")
    except Exception as e:
        logger.critical(f"Failed to initialize IMAP inbox for {
                        account_name}: {e}")
        mail.logout()
        return

    try:
        while True:
            try:
                mail.select('inbox')
                status, data = mail.uid(
                    'SEARCH', None, f'UID {last_uid + 1}:*')
                email_uids = data[0].split()

                if not email_uids:
                    time.sleep(10)
                    continue

                for uid in email_uids:
                    uid_int = int(uid)
                    if uid_int in processed_uids:
                        continue

                    status, data = mail.uid('FETCH', uid, '(RFC822)')
                    if status != 'OK':
                        logger.warning(
                            f"Failed to fetch email UID {uid.decode()}")
                        continue

                    raw_email = data[0][1]
                    msg = email.message_from_bytes(raw_email)

                    subject = msg.get("Subject", "No Subject")
                    decoded_subject = str(decode_header(subject)[0][0], errors="ignore") if isinstance(
                        decode_header(subject)[0][0], bytes) else subject

                    body, links, sender, cc, forwarded_history = extract_text_content(
                        msg)

                    if is_spam_via_gpt(decoded_subject, body, links, sender, cc, forwarded_history, logger):
                        logger.info(f"Spam detected: {decoded_subject}")
                        mail.uid('COPY', uid, spam_folder)
                        mail.uid('STORE', uid, '+FLAGS', '\\Deleted')

                    mail.uid('STORE', uid, '-FLAGS', '(\\Seen)')
                    last_uid = max(last_uid, uid_int)
                    processed_uids.add(uid_int)

                mail.expunge()

            except imaplib.IMAP4.abort:
                logger.warning("IMAP connection aborted. Reconnecting...")
                mail = imaplib.IMAP4_SSL(imap_host)
                mail.login(email_user, email_pass)
            except Exception as e:
                logger.error(f"Error during processing: {e}")
                time.sleep(10)

    except KeyboardInterrupt:
        logger.info(f"Script stopped for {account_name}")
    finally:
        try:
            mail.close()
            logger.info(f"IMAP connection closed for {account_name}")
        except imaplib.IMAP4.abort:
            logger.warning(
                f"Error while closing the mailbox for {account_name}")
        mail.logout()
        logger.info(f"Logged out of IMAP server for {account_name}")


if __name__ == "__main__":
    processes = []
    for account_name, email_user in email_accounts.items():
        p = Process(target=process_email_account,
                    args=(account_name, email_user))
        p.start()
        processes.append(p)

    for p in processes:
        p.join()


