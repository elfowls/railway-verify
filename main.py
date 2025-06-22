import dns.resolver
import socket
import time
import random
import string
import email.utils
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr
from typing import List, Optional, Dict

# ──────────────────────────────────────────────────────────────────────────────
# FASTAPI SETUP & CORS
# ──────────────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="SMTP Email Verifier API",
    description="Batch-verify email addresses using SMTP-handshake + timing for catch-all domains, optimized for bulk and fast response.",
    version="1.2.0"
)

# Allow only specific domains
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
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────
FROM_ADDRESS_TEMPLATE = "verify@{}"
SOCKET_TIMEOUT = 5.0
NUM_CALIBRATE = 2
RCPT_RETRIES = 1
TIMING_CUSHION = 0.05
executor = ThreadPoolExecutor(max_workers=50)

FREE_MAIL_DOMAINS = {"gmail.com","yahoo.com","outlook.com","hotmail.com","aol.com","icloud.com","protonmail.com","zoho.com"}
DISPOSABLE_DOMAINS = {"mailinator.com","10minutemail.com","yopmail.com","tempmail.com","discard.email","guerrillamail.com"}
ROLE_LOCALS = {"admin","administrator","support","info","sales","marketing","billing","webmaster","postmaster","contact","help","service"}

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
# HELPERS: DNS & SMTP
# ──────────────────────────────────────────────────────────────────────────────
def get_mx_hosts(domain: str) -> List[str]:
    try:
        answers = dns.resolver.resolve(domain, "MX")
        mx_list = sorted([(r.preference, r.exchange.to_text().rstrip(".")) for r in answers], key=lambda x:x[0])
        return [h for (_,h) in mx_list]
    except:
        for rd in ("A","AAAA"):
            try:
                dns.resolver.resolve(domain, rd)
                return [domain]
            except:
                continue
    return []

def connect_smtp(mx_host: str) -> socket.socket:
    sock = socket.create_connection((mx_host,25),timeout=SOCKET_TIMEOUT)
    sock.settimeout(SOCKET_TIMEOUT)
    return sock

def recv_line(sock: socket.socket) -> str:
    data=b""
    while not data.endswith(b"\r\n"):
        ch=sock.recv(1)
        if not ch: break
        data+=ch
    return data.decode(errors="ignore").rstrip("\r\n")

def send_line(sock: socket.socket,line:str): sock.sendall((line+"\r\n").encode())

def parse_code(line:str)->int:
    try: return int(line[:3])
    except: return -1

def smtp_ehlo(sock:socket.socket,domain:str):
    send_line(sock,f"EHLO {domain}")
    while True:
        ln=recv_line(sock)
        if not ln.startswith("250-"): break

def smtp_mail_from(sock:socket.socket,from_addr:str)->int:
    send_line(sock,f"MAIL FROM:<{from_addr}>")
    return parse_code(recv_line(sock))

def smtp_rcpt_to(sock:socket.socket,to_addr:str)->(int,float,str):
    st=time.time()
    send_line(sock,f"RCPT TO:<{to_addr}>")
    resp=recv_line(sock)
    return parse_code(resp),time.time()-st,resp

def smtp_quit(sock:socket.socket):
    try: send_line(sock,"QUIT"); recv_line(sock)
    finally: sock.close()

# ──────────────────────────────────────────────────────────────────────────────
# CATCH-ALL & TIMING
# ──────────────────────────────────────────────────────────────────────────────
def detect_catch_all(mx,dom,frm)->bool:
    for _ in range(NUM_CALIBRATE):
        test=f"{uuid.uuid4().hex[:8]}@{dom}"
        try:
            s=connect_smtp(mx); recv_line(s); smtp_ehlo(s,dom)
            if smtp_mail_from(s,frm)!=250: smtp_quit(s); return False
            code,_,_=smtp_rcpt_to(s,test); smtp_quit(s)
            if code<200 or code>=300: return False
        except: return False
    return True

def calibrate_fake_timing(mx,dom,frm)->float:
    ts=[]
    for _ in range(NUM_CALIBRATE):
        fake=f"{uuid.uuid4().hex[:8]}@{dom}"
        try:
            s=connect_smtp(mx); recv_line(s); smtp_ehlo(s,dom)
            smtp_mail_from(s,frm)
            code,delta,_=smtp_rcpt_to(s,fake)
            if 200<=code<300: ts.append(delta)
            smtp_quit(s)
        except: pass
    return sum(ts)/len(ts) if ts else 0.0

# ──────────────────────────────────────────────────────────────────────────────
# VERIFICATION FUNCTIONS
# ──────────────────────────────────────────────────────────────────────────────
def verify_simple(mx,dom,frm,target)->PerAddressResult:
    start=time.time(); res=PerAddressResult(addr=target,method="simple")
    res.mx=mx
    try:
        s=connect_smtp(mx); recv_line(s); smtp_ehlo(s,dom)
        smtp_mail_from(s,frm); code,_,msg=smtp_rcpt_to(s,target)
        res.rcpt_code=code; res.rcpt_msg=msg
        if code>=500 and code<600: res.status="invalid"; smtp_quit(s)
        elif code>=400 and code<500: res.status="unknown_temp"; smtp_quit(s)
        else:
            send_line(s,"DATA"); dresp=recv_line(s); dcode=parse_code(dresp)
            res.data_code=dcode; res.data_msg=dresp
            if dcode==354:
                send_line(s,f"Date: {email.utils.formatdate(localtime=False)}")
                send_line(s,f"From: <{frm}>")
                send_line(s,f"To: <{target}>")
                send_line(s,"Subject: Verification Test")
                send_line(s,f"Message-ID: <{uuid.uuid4().hex}@{dom}>")
                send_line(s,"MIME-Version: 1.0"); send_line(s,"Content-Type: text/plain; charset=UTF-8")
                send_line(s,""); send_line(s,"This is a minimal verification message."); send_line(s,".")
                d2=recv_line(s); d2c=parse_code(d2)
                res.data_code=d2c; res.data_msg=d2
                res.status="valid" if 200<=d2c<300 else "invalid" if d2c>=500 else "unknown_temp"
            else: res.status="unknown"
            smtp_quit(s)
    except: res.status="connect_failed"
    fill_additional_fields(res,dom,False)
    res.verification_time=time.time()-start; return res

def verify_with_timing(mx,dom,frm,target,avg)->PerAddressResult:
    start=time.time(); res=PerAddressResult(addr=target,method="timing")
    res.mx=mx
    try:
        s=connect_smtp(mx); recv_line(s); smtp_ehlo(s,dom)
        smtp_mail_from(s,frm); code,delta,msg=smtp_rcpt_to(s,target)
        res.rcpt_code=code; res.rcpt_time=delta; res.rcpt_msg=msg
        if code>=500 and code<600: res.status="invalid"
        elif code>=400 and code<500: res.status="unknown_temp"
        else: res.status="valid" if delta>avg+TIMING_CUSHION else "invalid"
        smtp_quit(s)
    except: res.status="connect_failed"
    fill_additional_fields(res,dom,True)
    res.verification_time=time.time()-start; return res

# ──────────────────────────────────────────────────────────────────────────────
# EXTRA FIELDS
# ──────────────────────────────────────────────────────────────────────────────
def infer_mx_provider(mx):
    m=mx.lower()
    if "google" in m or m.endswith("gmail.com"): return "Google"
    if any(k in m for k in ("outlook","office365","hotmail","live")): return "Microsoft"
    return "Other/Unknown"

def infer_free(dom): return dom.lower() in FREE_MAIL_DOMAINS

def infer_disposable(dom): return dom.lower() in DISPOSABLE_DOMAINS

def infer_role(local): return local.lower() in ROLE_LOCALS

def infer_deliverability(st): return "deliverable" if st=="valid" else "undeliverable" if st=="invalid" else "risky"

def infer_score(st): return 1.0 if st=="valid" else 0.0 if st=="invalid" else 0.5

def fill_additional_fields(res,dom,ca):
    res.mx_provider=infer_mx_provider(res.mx or "")
    res.catch_all=ca
    res.deliverability=infer_deliverability(res.status or "")
    res.score=infer_score(res.status or "")
    local=res.addr.split('@',1)[0]
    res.free=infer_free(dom or ""); res.disposable=infer_disposable(dom or "")
    res.role=infer_role(local)
    res.result=res.status if res.status in ("valid","invalid") else "risky"

# ──────────────────────────────────────────────────────────────────────────────
# BULK VERIFY
# ──────────────────────────────────────────────────────────────────────────────
def verify_bulk(address_list:List[str])->Dict[str,PerAddressResult]:
    doms=defaultdict(list)
    for a in address_list:
        if '@' not in a: doms[None].append(a)
        else: _,d=a.rsplit('@',1); doms[d].append(a)
    out={}
    for d,addrs in doms.items():
        if d is None:
            for a in addrs:
                r=PerAddressResult(addr=a,status="invalid_format"); fill_additional_fields(r,"",False); r.verification_time=0.0; out[a]=r
            continue
        mxs=get_mx_hosts(d)
        if not mxs:
            for a in addrs:
                r=PerAddressResult(addr=a,status="invalid_domain"); fill_additional_fields(r,d,False); r.verification_time=0.0; out[a]=r
            continue
        mx=mxs[0]; frm=FROM_ADDRESS_TEMPLATE.format(d)
        ca=detect_catch_all(mx,d,frm)
        avg=calibrate_fake_timing(mx,d,frm) if ca else 0.0
        for a in addrs:
            r=verify_with_timing(mx,d,frm,a,avg) if ca else verify_simple(mx,d,frm,a)
            out[a]=r
    return out

# ──────────────────────────────────────────────────────────────────────────────
# ENDPOINT
# ──────────────────────────────────────────────────────────────────────────────
@app.post("/verify",response_model=VerifyResponse)
def batch_verify(req:VerifyRequest):
    if len(req.emails)>500: raise HTTPException(400,"Max 500 emails per request.")
    return VerifyResponse(batch_id=req.batch_id,results=verify_bulk(req.emails))
