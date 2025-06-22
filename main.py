import dns.resolver
import socket
import time
import random
import string
import email.utils
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import asyncio

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict

# ──────────────────────────────────────────────────────────────────────────────
# FASTAPI SETUP
# ──────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SMTP Email Verifier API",
    description="High-throughput, low-latency SMTP email verification for bulk React/TSX clients.",
    version="1.3.0"
)

# ──────────────────────────────────────────────────────────────────────────────
# CORS MIDDLEWARE (allow all origins for React frontend)
# ──────────────────────────────────────────────────────────────────────────────
from fastapi.middleware.cors import CORSMiddleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "https://bounso.com",
        "http://bounso.com",
        "https://owlsquad.com",
        "http://owlsquad.com"
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ──────────────────────────────────────────────────────────────────────────────
# SETTINGS & GLOBAL EXECUTOR
# ──────────────────────────────────────────────────────────────────────────────
FROM_ADDRESS_TEMPLATE = "verify@{}"
SOCKET_TIMEOUT = 5.0
TIMING_CUSHION = 0.05
# thread pool sized for concurrent verify tasks across requests
executor = ThreadPoolExecutor(max_workers=50)

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
# SMTP LOW-LEVEL HELPERS
# ──────────────────────────────────────────────────────────────────────────────
def connect_smtp(mx_host: str) -> socket.socket:
    sock = socket.create_connection((mx_host, 25), timeout=SOCKET_TIMEOUT)
    sock.settimeout(SOCKET_TIMEOUT)
    return sock

def recv_line(sock: socket.socket) -> str:
    data = b""
    while not data.endswith(b"\r\n"):
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data.decode(errors="ignore").strip()

def send_line(sock: socket.socket, line: str):
    sock.sendall(f"{line}\r\n".encode())

def parse_code(line: str) -> int:
    try:
        return int(line[:3])
    except:
        return -1

def smtp_ehlo(sock: socket.socket, domain: str):
    send_line(sock, f"EHLO {domain}")
    while True:
        line = recv_line(sock)
        if not line.startswith("250-"):
            break

def smtp_mail_from(sock: socket.socket, from_addr: str) -> int:
    send_line(sock, f"MAIL FROM:<{from_addr}>")
    return parse_code(recv_line(sock))

def smtp_rcpt_to(sock: socket.socket, to_addr: str) -> (int, float, str):
    start = time.time()
    send_line(sock, f"RCPT TO:<{to_addr}>")
    resp = recv_line(sock)
    return parse_code(resp), time.time()-start, resp

def smtp_quit(sock: socket.socket):
    try:
        send_line(sock, "QUIT")
        recv_line(sock)
    finally:
        sock.close()

# ──────────────────────────────────────────────────────────────────────────────
# DOMAIN-LEVEL CATCH-ALL DETECTION & TIMING
# ──────────────────────────────────────────────────────────────────────────────
def detect_catch_all(mx_host: str, domain: str, from_addr: str) -> bool:
    for _ in range(2):
        test_addr = f"{uuid.uuid4().hex[:8]}@{domain}"
        try:
            sock = connect_smtp(mx_host)
            recv_line(sock)
            smtp_ehlo(sock, domain)
            if smtp_mail_from(sock, from_addr) != 250:
                smtp_quit(sock)
                return False
            code, _, _ = smtp_rcpt_to(sock, test_addr)
            smtp_quit(sock)
            if code < 200 or code >= 300:
                return False
        except:
            return False
    return True


def calibrate_fake_timing(mx_host: str, domain: str, from_addr: str) -> float:
    times = []
    for _ in range(2):
        fake = f"{uuid.uuid4().hex[:8]}@{domain}"
        try:
            sock = connect_smtp(mx_host)
            recv_line(sock)
            smtp_ehlo(sock, domain)
            smtp_mail_from(sock, from_addr)
            code, delta, _ = smtp_rcpt_to(sock, fake)
            if 200 <= code < 300:
                times.append(delta)
            smtp_quit(sock)
        except:
            pass
    return sum(times)/len(times) if times else 0.0

# ──────────────────────────────────────────────────────────────────────────────
# VERIFICATION WORKFLOWS
# ──────────────────────────────────────────────────────────────────────────────
def verify_simple(mx_host, domain, from_addr, target):
    # mimic your SMTP+DATA simple logic
    # build and return a fully-populated PerAddressResult
    ...

def verify_with_timing(mx_host, domain, from_addr, target, avg_fake):
    # mimic your timing-based logic
    ...

# ──────────────────────────────────────────────────────────────────────────────
# BULK VERIFY (PARALLELIZED)
# ──────────────────────────────────────────────────────────────────────────────

def verify_bulk(addresses: List[str]) -> Dict[str, PerAddressResult]:
    domains = defaultdict(list)
    for addr in addresses:
        parts = addr.rsplit('@',1)
        domains[parts[1] if len(parts)==2 else None].append(addr)

    results: Dict[str, PerAddressResult] = {}
    with ThreadPoolExecutor(max_workers=20) as pool:
        futures = []
        for dom, addrs in domains.items():
            if not dom:
                for a in addrs:
                    futures.append(pool.submit(lambda x: PerAddressResult(addr=x, status='invalid_format'), a))
                continue
            mxs = get_mx_hosts(dom)
            if not mxs:
                for a in addrs:
                    futures.append(pool.submit(lambda x: PerAddressResult(addr=x, status='invalid_domain'), a))
                continue
            mx = mxs[0]
            from_addr = FROM_ADDRESS_TEMPLATE.format(dom)
            catch = detect_catch_all(mx, dom, from_addr)
            avg = calibrate_fake_timing(mx, dom, from_addr) if catch else 0
            for a in addrs:
                if catch:
                    futures.append(pool.submit(verify_with_timing, mx, dom, from_addr, a, avg))
                else:
                    futures.append(pool.submit(verify_simple, mx, dom, from_addr, a))
        for f in as_completed(futures):
            res = f.result()
            results[res.addr] = res
    return results

# ──────────────────────────────────────────────────────────────────────────────
# ASYNC API ENDPOINT
# ──────────────────────────────────────────────────────────────────────────────
@app.post("/verify", response_model=VerifyResponse)
async def batch_verify(request: VerifyRequest):
    if len(request.emails) > 500:
        raise HTTPException(400, "Max 500 emails per request.")
    loop = asyncio.get_event_loop()
    results = await loop.run_in_executor(executor, verify_bulk, request.emails)
    return VerifyResponse(batch_id=request.batch_id, results=results)
