import dns.resolver
import socket
import time
import random
import string
import email.utils
import uuid
from collections import defaultdict

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict

# ──────────────────────────────────────────────────────────────────────────────
# FASTAPI SETUP WITH CORS
# ──────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="SMTP Email Verifier API",
    description="Batch‐verify email addresses using SMTP‐handshake + timing for catch‐all domains, "
                "with extended metadata and CORS enabled for bounso.com.",
    version="1.1.0"
)

# ──────────────────────────────────────────────────────────────────────────────
# ADD CORS MIDDLEWARE
# ──────────────────────────────────────────────────────────────────────────────

origins = [
    "https://bounso.com",
    "http://bounso.com",
    # You may add local dev origins here:
    # "http://localhost:3000", "http://127.0.0.1:3000"
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,            
    allow_credentials=True,
    allow_methods=["*"],              
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION (Adjust as needed)
# ──────────────────────────────────────────────────────────────────────────────

FROM_ADDRESS_TEMPLATE = "verify@{}"
SOCKET_TIMEOUT = 5.0
NUM_CALIBRATE = 2
RCPT_RETRIES = 1
TIMING_CUSHION = 0.05

FREE_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "aol.com", "icloud.com", "protonmail.com", "zoho.com"
}

DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "yopmail.com",
    "tempmail.com", "discard.email", "guerrillamail.com"
}

ROLE_LOCALS = {
    "admin", "administrator", "support", "info", "sales", "marketing",
    "billing", "webmaster", "postmaster", "contact", "help", "service"
}

# ──────────────────────────────────────────────────────────────────────────────
# REQUEST / RESPONSE MODELS
# ──────────────────────────────────────────────────────────────────────────────

class VerifyRequest(BaseModel):
    batch_id: Optional[str]
    emails: List[EmailStr]

class PerAddressResult(BaseModel):
    addr: EmailStr
    mx: Optional[str] = None
    mx_provider: Optional[str] = None
    deliverability: Optional[str] = None
    score: Optional[float] = None
    free: Optional[bool] = None
    disposable: Optional[bool] = None
    role: Optional[bool] = None
    catch_all: Optional[bool] = None
    result: Optional[str] = None
    verification_time: Optional[float] = None

    method: Optional[str] = None
    status: Optional[str] = None
    rcpt_code: Optional[int] = None
    rcpt_time: Optional[float] = None
    rcpt_msg: Optional[str] = None
    data_code: Optional[int] = None
    data_msg: Optional[str] = None

class VerifyResponse(BaseModel):
    batch_id: Optional[str]
    results: Dict[EmailStr, PerAddressResult]

# ──────────────────────────────────────────────────────────────────────────────
# HELPER FUNCTIONS: DNS + RAW SMTP PROBES
# ──────────────────────────────────────────────────────────────────────────────

def get_mx_hosts(domain: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_list = [(r.preference, r.exchange.to_text().rstrip(".")) for r in answers]
        mx_list.sort(key=lambda x: x[0])
        return [host for (_, host) in mx_list]
    except Exception:
        # Fallback to A/AAAA
        try:
            dns.resolver.resolve(domain, "A")
            return [domain]
        except Exception:
            pass
        try:
            dns.resolver.resolve(domain, "AAAA")
            return [domain]
        except Exception:
            pass
    return []

def recv_line(sock: socket.socket) -> str:
    data = b""
    while True:
        ch = sock.recv(1)
        if not ch:
            break
        data += ch
        if data.endswith(b"\r\n"):
            break
    return data.decode(errors="ignore").rstrip("\r\n")

def send_line(sock: socket.socket, line: str):
    sock.sendall((line + "\r\n").encode())

def parse_code(line: str) -> int:
    try:
        return int(line[:3])
    except Exception:
        return -1

def connect_smtp(mx_host: str) -> socket.socket:
    sock = socket.create_connection((mx_host, 25), timeout=SOCKET_TIMEOUT)
    sock.settimeout(SOCKET_TIMEOUT)
    return sock

def smtp_ehlo(sock: socket.socket, domain: str):
    send_line(sock, f"EHLO {domain}")
    while True:
        line = recv_line(sock)
        if not line.startswith("250-"):
            break

def smtp_mail_from(sock: socket.socket, from_addr: str) -> int:
    send_line(sock, f"MAIL FROM:<{from_addr}>")
    resp = recv_line(sock)
    return parse_code(resp)

def smtp_rcpt_to(sock: socket.socket, to_addr: str) -> (int, float, str):
    start = time.time()
    send_line(sock, f"RCPT TO:<{to_addr}>")
    resp = recv_line(sock)
    elapsed = time.time() - start
    return parse_code(resp), elapsed, resp

def smtp_quit(sock: socket.socket):
    try:
        send_line(sock, "QUIT")
        _ = recv_line(sock)
    except Exception:
        pass
    finally:
        sock.close()

# ──────────────────────────────────────────────────────────────────────────────
# CATCH-ALL DETECTION
# ──────────────────────────────────────────────────────────────────────────────

def detect_catch_all(mx_host: str, domain: str, from_addr: str) -> bool:
    for _ in range(NUM_CALIBRATE):
        rand_local = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        test_addr = f"{rand_local}@{domain}"
        try:
            sock = connect_smtp(mx_host)
            recv_line(sock)
            smtp_ehlo(sock, domain)
            code_mail = smtp_mail_from(sock, from_addr)
            if code_mail != 250:
                smtp_quit(sock)
                return False
            attempt = 0
            while attempt <= RCPT_RETRIES:
                code_rcpt, _, _ = smtp_rcpt_to(sock, test_addr)
                if 500 <= code_rcpt < 600:
                    smtp_quit(sock)
                    return False
                if 200 <= code_rcpt < 300:
                    break
                if 400 <= code_rcpt < 500:
                    attempt += 1
                    time.sleep(0.2 * attempt)
                    continue
                smtp_quit(sock)
                return False
            smtp_quit(sock)
        except Exception:
            return False
    return True

# ──────────────────────────────────────────────────────────────────────────────
# TIMING-BASED VALIDATION UNDER CATCH-ALL
# ──────────────────────────────────────────────────────────────────────────────

def calibrate_fake_timing(mx_host: str, domain: str, from_addr: str) -> float:
    times = []
    for _ in range(NUM_CALIBRATE):
        rand_local = "".join(random.choices(string.ascii_lowercase + string.digits, k=10))
        test_addr = f"{rand_local}@{domain}"
        try:
            sock = connect_smtp(mx_host)
            recv_line(sock)
            smtp_ehlo(sock, domain)
            smtp_mail_from(sock, from_addr)
            code_rcpt, rcpt_time, _ = smtp_rcpt_to(sock, test_addr)
            if 200 <= code_rcpt < 300:
                times.append(rcpt_time)
            smtp_quit(sock)
        except Exception:
            continue
    return sum(times) / len(times) if times else 0.0

def verify_with_timing(mx_host: str, domain: str, from_addr: str, target_addr: str, avg_fake: float) -> PerAddressResult:
    start_time = time.time()
    result = PerAddressResult(addr=target_addr)
    result.method = "timing"
    result.mx = mx_host
    try:
        sock = connect_smtp(mx_host)
        recv_line(sock)
        smtp_ehlo(sock, domain)
        smtp_mail_from(sock, from_addr)
        code_rcpt, rcpt_time, rcpt_msg = smtp_rcpt_to(sock, target_addr)
        result.rcpt_code = code_rcpt
        result.rcpt_time = rcpt_time
        result.rcpt_msg = rcpt_msg

        if 500 <= code_rcpt < 600:
            result.status = "invalid"
        elif 400 <= code_rcpt < 500:
            result.status = "unknown_temp"
        else:
            if rcpt_time > avg_fake + TIMING_CUSHION:
                result.status = "valid"
            else:
                result.status = "invalid"
        smtp_quit(sock)
    except Exception:
        result.status = "connect_failed"
    fill_additional_fields(result, domain, catch_all=True)
    result.verification_time = time.time() - start_time
    return result

# ──────────────────────────────────────────────────────────────────────────────
# SIMPLE SMTP VALIDATION (NON-CATCH-ALL)
# ──────────────────────────────────────────────────────────────────────────────

def verify_simple(mx_host: str, domain: str, from_addr: str, target_addr: str) -> PerAddressResult:
    start_time = time.time()
    result = PerAddressResult(addr=target_addr)
    result.method = "simple"
    result.mx = mx_host
    try:
        sock = connect_smtp(mx_host)
        recv_line(sock)
        smtp_ehlo(sock, domain)
        smtp_mail_from(sock, from_addr)
        code_rcpt, _, rcpt_msg = smtp_rcpt_to(sock, target_addr)
        result.rcpt_code = code_rcpt
        result.rcpt_msg = rcpt_msg

        if 500 <= code_rcpt < 600:
            result.status = "invalid"
            smtp_quit(sock)
            fill_additional_fields(result, domain, catch_all=False)
            result.verification_time = time.time() - start_time
            return result
        if 400 <= code_rcpt < 500:
            result.status = "unknown_temp"
            smtp_quit(sock)
            fill_additional_fields(result, domain, catch_all=False)
            result.verification_time = time.time() - start_time
            return result

        # RCPT accepted → DATA
        send_line(sock, "DATA")
        data_resp = recv_line(sock)
        data_code = parse_code(data_resp)
        result.data_code = data_code
        result.data_msg = data_resp

        if 500 <= data_code < 600:
            result.status = "invalid"
            smtp_quit(sock)
            fill_additional_fields(result, domain, catch_all=False)
            result.verification_time = time.time() - start_time
            return result

        if data_code == 354:
            send_line(sock, f"Date: {email.utils.formatdate(localtime=False)}")
            send_line(sock, f"From: <{from_addr}>")
            send_line(sock, f"To: <{target_addr}>")
            send_line(sock, "Subject: Verification Test")
            send_line(sock, f"Message-ID: <{uuid.uuid4().hex}@{domain}>")
            send_line(sock, "MIME-Version: 1.0")
            send_line(sock, "Content-Type: text/plain; charset=UTF-8")
            send_line(sock, "")
            send_line(sock, "This is a minimal verification message.")
            send_line(sock, ".")
            data2_resp = recv_line(sock)
            data2_code = parse_code(data2_resp)
            result.data_code = data2_code
            result.data_msg = data2_resp

            if 200 <= data2_code < 300:
                result.status = "valid"
            elif 500 <= data2_code < 600:
                result.status = "invalid"
            else:
                result.status = "unknown_temp"
        else:
            result.status = "unknown"
        smtp_quit(sock)
    except Exception:
        result.status = "connect_failed"

    fill_additional_fields(result, domain, catch_all=False)
    result.verification_time = time.time() - start_time
    return result

# ──────────────────────────────────────────────────────────────────────────────
# ADDITIONAL FIELD CALCULATION
# ──────────────────────────────────────────────────────────────────────────────

def infer_mx_provider(mx_host: str) -> str:
    mx_lower = (mx_host or "").lower()
    if "google" in mx_lower or mx_lower.endswith("gmail.com"):
        return "Google"
    if "outlook" in mx_lower or "office365" in mx_lower or "hotmail" in mx_lower or "live" in mx_lower:
        return "Microsoft"
    return "Other/Unknown"

def infer_free(domain: str) -> bool:
    return domain.lower() in FREE_MAIL_DOMAINS

def infer_disposable(domain: str) -> bool:
    return domain.lower() in DISPOSABLE_DOMAINS

def infer_role(local: str) -> bool:
    return local.lower() in ROLE_LOCALS

def infer_deliverability(status: str) -> str:
    if status == "valid":
        return "deliverable"
    if status == "invalid":
        return "undeliverable"
    return "risky"

def infer_score(status: str) -> float:
    if status == "valid":
        return 1.0
    if status == "invalid":
        return 0.0
    return 0.5

def fill_additional_fields(result: PerAddressResult, domain: str, catch_all: bool):
    result.mx_provider = infer_mx_provider(result.mx or "")
    result.catch_all = catch_all
    result.deliverability = infer_deliverability(result.status or "")
    result.score = infer_score(result.status or "")
    local_part = result.addr.split("@", 1)[0]
    result.free = infer_free(domain or "")
    result.disposable = infer_disposable(domain or "")
    result.role = infer_role(local_part)
    if result.status == "valid":
        result.result = "valid"
    elif result.status == "invalid":
        result.result = "invalid"
    else:
        result.result = "risky"

# ──────────────────────────────────────────────────────────────────────────────
# MAIN: MULTIPLE EMAIL VERIFICATION
# ──────────────────────────────────────────────────────────────────────────────

def verify_bulk(address_list: List[str]) -> Dict[str, PerAddressResult]:
    domains = defaultdict(list)
    for addr in address_list:
        if "@" not in addr:
            domains[None].append(addr)
        else:
            local, domain = addr.rsplit("@", 1)
            domains[domain].append(addr)

    results: Dict[str, PerAddressResult] = {}

    for domain, addrs in domains.items():
        if domain is None:
            for addr in addrs:
                res = PerAddressResult(addr=addr, status="invalid_format")
                res.mx = None
                fill_additional_fields(res, "", catch_all=False)
                res.verification_time = 0.0
                results[addr] = res
            continue

        mx_hosts = get_mx_hosts(domain)
        if not mx_hosts:
            for addr in addrs:
                res = PerAddressResult(addr=addr, status="invalid_domain")
                res.mx = None
                fill_additional_fields(res, domain, catch_all=False)
                res.verification_time = 0.0
                results[addr] = res
            continue

        mx_host = mx_hosts[0]
        from_addr = FROM_ADDRESS_TEMPLATE.format(domain)

        is_catch_all = detect_catch_all(mx_host, domain, from_addr)

        if not is_catch_all:
            for addr in addrs:
                res = verify_simple(mx_host, domain, from_addr, addr)
                res.mx = mx_host
                fill_additional_fields(res, domain, catch_all=False)
                results[addr] = res
        else:
            avg_fake = calibrate_fake_timing(mx_host, domain, from_addr)
            for addr in addrs:
                if avg_fake <= 0:
                    res = PerAddressResult(addr=addr)
                    res.method = "timing"
                    res.status = "unknown_catchall"
                    res.mx = mx_host
                    fill_additional_fields(res, domain, catch_all=True)
                    res.verification_time = 0.0
                    results[addr] = res
                else:
                    res = verify_with_timing(mx_host, domain, from_addr, addr, avg_fake)
                    results[addr] = res

    return results

# ──────────────────────────────────────────────────────────────────────────────
# API ROUTE
# ──────────────────────────────────────────────────────────────────────────────

@app.post("/verify", response_model=VerifyResponse)
def batch_verify(request: VerifyRequest):
    if len(request.emails) > 200:
        raise HTTPException(status_code=400, detail="Maximum 200 emails per request.")
    raw_results = verify_bulk(request.emails)
    return VerifyResponse(batch_id=request.batch_id, results=raw_results)
