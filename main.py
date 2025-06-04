from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List
import smtplib, dns.resolver, random, string, time

app = FastAPI()

# Allow CORS for your frontend
origins = [
    "https://bounso.com",
    "https://www.bounso.com"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Email list model
class EmailList(BaseModel):
    emails: List[str]

ROLE_BASED_PREFIXES = ['admin', 'info', 'support', 'sales', 'contact', 'hello', 'billing', 'team', 'help', 'office']
FREE_EMAIL_PROVIDERS = [
    'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'live.com',
    'aol.com', 'icloud.com', 'protonmail.com', 'zoho.com', 'gmx.com',
    'mail.com', 'yandex.com'
]
DISPOSABLE_EMAIL_PROVIDERS = [
    'mailinator.com', 'guerrillamail.com', '10minutemail.com',
    'tempmail.com', 'trashmail.com', 'getnada.com', 'moakt.com',
    'throwawaymail.com', 'emailondeck.com', 'fakeinbox.com'
]

def get_mx_record(domain):
    try:
        answers = dns.resolver.resolve(domain, 'MX')
        return sorted([(r.preference, str(r.exchange).rstrip('.')) for r in answers])[0][1]
    except Exception:
        return None

def generate_fake_email(domain):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=12)) + '@' + domain

def smtp_check(email, mx, from_address='verifyemails@gmail.com'):
    try:
        server = smtplib.SMTP(timeout=10)
        server.connect(mx)
        server.helo('example.com')
        server.mail(from_address)
        start = time.perf_counter()
        code, _ = server.rcpt(email)
        delay = time.perf_counter() - start
        try:
            server.docmd("DATA")
            msg = (f"From: Verifier <{from_address}>\r\n"
                   f"To: Target <{email}>\r\n"
                   f"Subject: Email Verification Test\r\n"
                   f"Date: {time.strftime('%a, %d %b %Y %H:%M:%S +0000')}\r\n"
                   f"\r\nTesting mailbox existence only.\r\n.\r\n")
            server.send(msg)
        except:
            pass
        server.quit()
        return code, delay
    except Exception:
        return 0, 0

def is_role_based(email):
    local_part = email.split('@')[0].lower()
    return any(local_part.startswith(prefix) for prefix in ROLE_BASED_PREFIXES)

def is_free_provider(email):
    domain = email.split('@')[-1].lower()
    return domain in FREE_EMAIL_PROVIDERS

def is_disposable_email(email):
    domain = email.split('@')[-1].lower()
    return domain in DISPOSABLE_EMAIL_PROVIDERS

def extract_smtp_provider(mx):
    if not mx:
        return ""
    mx_lower = mx.lower()
    if "google" in mx_lower:
        return "Google"
    elif "outlook" in mx_lower:
        return "Microsoft"
    return ""

def get_type_verdicts(email):
    role_based = is_role_based(email)
    free_provider = is_free_provider(email)
    disposable = is_disposable_email(email)

    role_verdict = "role-based" if role_based else "personal"
    free_verdict = "free" if free_provider else "business"
    disposable_verdict = "disposable" if disposable else "not-disposable"

    return role_based, free_provider, disposable, role_verdict, free_verdict, disposable_verdict

def verify_email(email):
    domain = email.split('@')[-1]
    mx = get_mx_record(domain)

    role_based, free_provider, disposable, role_verdict, free_verdict, disposable_verdict = get_type_verdicts(email)

    if not mx:
        return {
            "email": email,
            "verdict": "invalid",
            "reason": "MX lookup failed",
            "deliverability": "undeliverable",
            "role_based": role_based,
            "role_verdict": role_verdict,
            "free_provider": free_provider,
            "free_verdict": free_verdict,
            "disposable": disposable,
            "disposable_verdict": disposable_verdict,
            "smtp_provider": ""
        }

    fake_emails = [generate_fake_email(domain) for _ in range(3)]
    real_code, real_delay = smtp_check(email, mx)
    fake_delays = [smtp_check(fake, mx)[1] for fake in fake_emails]
    avg_fake_delay = sum(fake_delays) / len(fake_delays)
    delay_diff = round(real_delay - avg_fake_delay, 6)
    variance = round(abs(real_delay - avg_fake_delay), 6)

    if real_code != 250:
        verdict, reason, score, deliverability = "invalid", "RCPT rejected", 0.1, "undeliverable"
    elif all(smtp_check(fake, mx)[0] == 250 for fake in fake_emails):
        if variance < 0.025:
            verdict, reason, score, deliverability = "risky", "Catch-All - Riksy", 0.5, "risky"
        elif delay_diff > 0.02:
            verdict, reason, score, deliverability = "Catch-All likely-valid", "Real delay > fake delay", 0.8, "deliverable"
        else:
            verdict, reason, score, deliverability = "unclear", "Catch-All - unclear behavior", 0.4, "risky"
    else:
        verdict, reason, score, deliverability = "valid", "Real accepted, fakes rejected", 0.95, "deliverable"

    return {
        "email": email,
        "domain": domain,
        "mx": mx,
        "verdict": verdict,
        "reason": reason,
        "deliverability": deliverability,
        "score": score,
        "real_delay": round(real_delay, 6),
        "fake_avg_delay": round(avg_fake_delay, 6),
        "delay_diff": delay_diff,
        "variance": variance,
        "role_based": role_based,
        "role_verdict": role_verdict,
        "free_provider": free_provider,
        "free_verdict": free_verdict,
        "disposable": disposable,
        "disposable_verdict": disposable_verdict,
        "smtp_provider": extract_smtp_provider(mx)
    }

# API endpoint
@app.post("/verify")
async def verify(data: EmailList):
    results = [verify_email(email.strip()) for email in data.emails]
    return results
