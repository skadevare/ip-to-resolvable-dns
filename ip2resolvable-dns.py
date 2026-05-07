#!/usr/bin/env python3
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, RCODE
import socket

DOMAIN_SUFFIX = "your.domain.xyz."  # note trailing dot
LISTEN_IP = "0.0.0.0"
LISTEN_PORT = 53

def extract_ip(qname: str):
    # Expect: X.X.X.X.your.domain.xyz.
    if not qname.endswith(DOMAIN_SUFFIX):
        return None

    left = qname[:-len(DOMAIN_SUFFIX)]  # remove suffix
    # left should be like "8.8.8.8." or "8.8.8.8"
    left = left.strip(".")
    parts = left.split(".")
    if len(parts) != 4:
        return None

    ip = ".".join(parts)
    try:
        socket.inet_aton(ip)  # validates dotted-quad + octet range
        return ip
    except OSError:
        return None

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((LISTEN_IP, LISTEN_PORT))
print(f"Listening on {LISTEN_IP}:{LISTEN_PORT} for *.{DOMAIN_SUFFIX}")

while True:
    data, addr = sock.recvfrom(512)
    req = DNSRecord.parse(data)
    qname = str(req.q.qname)
    qtype = QTYPE[req.q.qtype]

    reply = DNSRecord(DNSHeader(id=req.header.id, qr=1, aa=1, ra=0), q=req.q)

    ip = extract_ip(qname)

    if ip and qtype in ("A", "ANY"):
        reply.add_answer(RR(rname=req.q.qname, rtype=QTYPE.A, rclass=1, ttl=60, rdata=A(ip)))
    else:
        # NXDOMAIN if it's not our pattern
        reply.header.rcode = RCODE.NXDOMAIN

    sock.sendto(reply.pack(), addr)
