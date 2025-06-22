import dns.resolver
import socket
import ssl
import time
import uuid
import email.utils
from collections import defaultdict
from typing import List, Dict, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr

# ──────────────────────────────────────────────────────────────────────────────
# FASTAPI SETUP & CORS
# ──────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SMTP Email Verifier API",
    description="Batch-verify emails via SMTP handshake + timing for catch-all domains.",
    version="1.4.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://bounso.com", "http://bounso.com",
        "https://owlsquad.com", "http://owlsquad.com"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────
FROM_ADDRESS_TEMPLATE = "verify@{}"
SOCKET_TIMEOUT = 5.0

FREE_MAIL_DOMAINS = {"gmail.com","yahoo.com","outlook.com","hotmail.com",
                     "aol.com","icloud.com","protonmail.com","zoho.com"}
DISPOSABLE_DOMAINS = {"mailinator.com","10minutemail.com","yopmail.com",
                      "tempmail.com","discard.email","guerrillamail.com"}
ROLE_LOCALS = {"admin","administrator","support","info","sales","marketing",
               "billing","webmaster","postmaster","contact","help","service"}

# ──────────────────────────────────────────────────────────────────────────────
# MODELS
# ──────────────────────────────────────────────────────────────────────────────
class VerifyRequest(BaseModel):
    batch_id: Optional[str] = None
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
# SMTP / DNS HELPERS
# ──────────────────────────────────────────────────────────────────────────────
def get_mx_hosts(domain: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_list = sorted(
            [(r.preference, r.exchange.to_text().rstrip(".")) for r in answers],
            key=lambda x: x[0]
        )
        return [h for (_, h) in mx_list]
    except:
        for rd in ("A","AAAA"):
            try:
                dns.resolver.resolve(domain, rd)
                return [domain]
            except:
                continue
    return []

def connect_smtp(mx_host: str, port: int = 25, use_tls: bool = False) -> socket.socket:
    sock = socket.create_connection((mx_host, port), timeout=SOCKET_TIMEOUT)
    sock.settimeout(SOCKET_TIMEOUT)
    sock.recv(1024)  # banner
    if use_tls:
        send_line(sock, "EHLO verifier")
        send_line(sock, "STARTTLS")
        resp = recv_line(sock)
        if int(resp[:3]) != 220:
            raise Exception("STARTTLS failed")
        sock = ssl.wrap_socket(sock)
        sock.settimeout(SOCKET_TIMEOUT)
    return sock

def recv_line(sock: socket.socket) -> str:
    data = b""
    while not data.endswith(b"\r\n"):
        ch = sock.recv(1)
        if not ch:
            break
        data += ch
    return data.decode(errors="ignore").rstrip("\r\n")

def send_line(sock: socket.socket, line: str):
    sock.sendall((line + "\r\n").encode())

def parse_code(line: str) -> int:
    try:
        return int(line[:3])
    except:
        return -1

def smtp_ehlo(sock: socket.socket, domain: str):
    send_line(sock, f"EHLO {domain}")
    while True:
        ln = recv_line(sock)
        if not ln.startswith("250-"):
            break

def smtp_mail_from(sock: socket.socket, from_addr: str) -> int:
    send_line(sock, f"MAIL FROM:<{from_addr}>")
    return parse_code(recv_line(sock))

def smtp_rcpt_to(sock: socket.socket, to_addr: str) -> (int, float, str):
    start = time.time()
    send_line(sock, f"RCPT TO:<{to_addr}>")
    resp = recv_line(sock)
    return parse_code(resp), time.time() - start, resp

def smtp_quit(sock: socket.socket):
    try:
        send_line(sock, "QUIT")
        recv_line(sock)
    finally:
        sock.close()

# ──────────────────────────────────────────────────────────────────────────────
# INFERENCE HELPERS
# ──────────────────────────────────────────────────────────────────────────────
def infer_mx_provider(mx: str) -> str:
    m = mx.lower()
    if "google" in m or m.endswith("gmail.com"):
        return "Google"
    if any(k in m for k in ("outlook","office365","hotmail","live")):
        return "Microsoft"
    return "Other/Unknown"

def infer_free(dom: str) -> bool:
    return dom.lower() in FREE_MAIL_DOMAINS

def infer_disposable(dom: str) -> bool:
    return dom.lower() in DISPOSABLE_DOMAINS

def infer_role(local: str) -> bool:
    return local.lower() in ROLE_LOCALS

def infer_deliverability(st: str) -> str:
    return "deliverable" if st=="valid" else "undeliverable" if st=="invalid" else "risky"

def infer_score(st: str) -> float:
    return 1.0 if st=="valid" else 0.0 if st=="invalid" else 0.5

def fill_additional_fields(res: PerAddressResult, dom: str, ca: bool):
    res.mx_provider    = infer_mx_provider(res.mx or "")
    res.catch_all      = ca
    res.deliverability = infer_deliverability(res.status or "")
    res.score          = infer_score(res.status or "")
    local = res.addr.split('@',1)[0]
    res.free           = infer_free(dom)
    res.disposable     = infer_disposable(dom)
    res.role           = infer_role(local)
    res.result         = res.status if res.status in ("valid","invalid") else "risky"

# ──────────────────────────────────────────────────────────────────────────────
# VERIFICATION METHODS
# ──────────────────────────────────────────────────────────────────────────────
def verify_simple(mx: str, dom: str, frm: str, target: str) -> PerAddressResult:
    start = time.time()
    res = PerAddressResult(addr=target, method="simple")
    res.mx = mx
    try:
        s = connect_smtp(mx); recv_line(s); smtp_ehlo(s, dom)
        smtp_mail_from(s, frm)
        code,_,msg = smtp_rcpt_to(s, target)

        # if 550 with anti-spoof → fallback to timing
        if code == 550 and "Anti-Spoofing policy" in msg:
            smtp_quit(s)
            return verify_with_timing(mx, dom, frm, target, 0.0)

        res.rcpt_code = code
        res.rcpt_msg  = msg

        if 500 <= code < 600:
            res.status = "invalid"
        elif 400 <= code < 500:
            res.status = "unknown_temp"
        else:
            send_line(s, "DATA"); dresp = recv_line(s); dcode = parse_code(dresp)
            if dcode == 354:
                send_line(s, f"Date: {email.utils.formatdate(localtime=False)}")
                send_line(s, f"From: <{frm}>")
                send_line(s, f"To: <{target}>")
                send_line(s, "Subject: Verification Test")
                send_line(s, f"Message-ID: <{uuid.uuid4().hex}@{dom}>")
                send_line(s, "MIME-Version: 1.0")
                send_line(s, "Content-Type: text/plain; charset=UTF-8")
                send_line(s, ""); send_line(s, "This is a minimal verification message.")
                send_line(s, ".")
                d2 = recv_line(s); d2c = parse_code(d2)
                res.data_code = d2c; res.data_msg = d2
                res.status = "valid" if 200 <= d2c < 300 else "invalid" if d2c >= 500 else "unknown_temp"
            else:
                res.status = "unknown"

        smtp_quit(s)

    except:
        res.status = "connect_failed"

    fill_additional_fields(res, dom, False)
    res.verification_time = time.time() - start
    return res

def verify_with_timing(mx: str, dom: str, frm: str, target: str, avg: float) -> PerAddressResult:
    start = time.time()
    res = PerAddressResult(addr=target, method="timing")
    res.mx = mx
    try:
        s = connect_smtp(mx); recv_line(s); smtp_ehlo(s, dom)
        smtp_mail_from(s, frm)
        code, delta, msg = smtp_rcpt_to(s, target)
        smtp_quit(s)
        res.rcpt_code = code
        res.rcpt_time = delta
        res.rcpt_msg  = msg
        if 500 <= code < 600:
            res.status = "invalid"
        elif 400 <= code < 500:
            res.status = "unknown_temp"
        else:
            res.status = "valid" if delta > avg else "invalid"
    except:
        res.status = "connect_failed"

    fill_additional_fields(res, dom, True)
    res.verification_time = time.time() - start
    return res

# ──────────────────────────────────────────────────────────────────────────────
# UTILITY: find a working MX that accepts EHLO
# ──────────────────────────────────────────────────────────────────────────────
def find_working_mx(domain: str) -> Optional[str]:
    for host in get_mx_hosts(domain):
        for port, tls in [(25, False), (587, True)]:
            try:
                s = connect_smtp(host, port, tls); smtp_ehlo(s, domain)
                smtp_quit(s)
                return host
            except:
                continue
    return None

# ──────────────────────────────────────────────────────────────────────────────
# BULK VERIFY
# ──────────────────────────────────────────────────────────────────────────────
def verify_bulk(address_list: List[str]) -> Dict[str, PerAddressResult]:
    out: Dict[str, PerAddressResult] = {}
    # 1) Group by domain
    domains = defaultdict(list)
    for a in address_list:
        if "@" in a:
            _, dom = a.rsplit("@",1)
            domains[dom].append(a)
        else:
            domains[None].append(a)

    # 2) Per-domain setup
    domain_info = {}
    for dom, addrs in domains.items():
        if dom is None:
            domain_info[dom] = {"method":"invalid_format"}
            continue

        mx = find_working_mx(dom) or (get_mx_hosts(dom)[0] if get_mx_hosts(dom) else None)
        if not mx:
            domain_info[dom] = {"method":"invalid_domain"}
            continue

        frm = FROM_ADDRESS_TEMPLATE.format(dom)
        fake = f"{uuid.uuid4().hex[:8]}@{dom}"
        try:
            s = connect_smtp(mx); recv_line(s); smtp_ehlo(s, dom)
            smtp_mail_from(s, frm)
            code, delta, _ = smtp_rcpt_to(s, fake)
            smtp_quit(s)
            is_ca = 200 <= code < 300
            fake_avg = delta if is_ca else 0.0
        except:
            is_ca = False
            fake_avg = 0.0

        method = "timing" if is_ca else "simple"
        domain_info[dom] = {"mx":mx, "method":method, "fake_avg":fake_avg}

    # 3) Verify each address
    for dom, addrs in domains.items():
        info = domain_info[dom]
        if info["method"] in ("invalid_format","invalid_domain"):
            for a in addrs:
                r = PerAddressResult(addr=a, status=info["method"])
                fill_additional_fields(r, dom or "", False)
                r.verification_time = 0.0
                out[a] = r
            continue

        mx, method, avg = info["mx"], info["method"], info["fake_avg"]
        frm = FROM_ADDRESS_TEMPLATE.format(dom)
        for a in addrs:
            if method == "simple":
                out[a] = verify_simple(mx, dom, frm, a)
            else:
                out[a] = verify_with_timing(mx, dom, frm, a, avg)

    return out

@app.post("/verify", response_model=VerifyResponse)
def batch_verify(req: VerifyRequest):
    if len(req.emails) > 500:
        raise HTTPException(400, "Max 500 emails per request.")
    results = verify_bulk(req.emails)
    return VerifyResponse(batch_id=req.batch_id, results=results)
