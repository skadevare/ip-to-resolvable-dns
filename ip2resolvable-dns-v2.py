#!/usr/bin/env python3
import ipaddress
import socket
from dnslib import DNSRecord, DNSHeader, RR, QTYPE, A, CNAME, RCODE

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DOMAIN_SUFFIX   = "your.domain.xyz."   # trailing dot required
LISTEN_IP       = "0.0.0.0"
LISTEN_PORT     = 53
TTL             = 60                    # seconds, for both A and CNAME answers
REDIRECT_TARGET = "cloudflare.com."    # CNAME returned to non-whitelisted sources

# ---------------------------------------------------------------------------
# Cloudflare IP ranges  (source: cloudflare.com/ips)
# Queries from these IPs receive the real A record.
# All other sources receive a CNAME pointing to REDIRECT_TARGET.
# ---------------------------------------------------------------------------

_CF_RANGES = [
    # IPv4
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22",   "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15",  "104.16.0.0/13",
    "104.24.0.0/14",   "172.64.0.0/13",   "131.0.72.0/22",
    # IPv6
    "2400:cb00::/32", "2606:4700::/32", "2803:f800::/32",
    "2405:b500::/32", "2405:8100::/32", "2a06:98c0::/29",
    "2c0f:f248::/32",
]
CF_NETWORKS = [ipaddress.ip_network(r) for r in _CF_RANGES]


def is_cf_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in CF_NETWORKS)
    except ValueError:
        return False


def extract_ip(qname: str):
    """Return the dotted-quad IPv4 embedded in qname, or None if not our pattern."""
    if not qname.endswith(DOMAIN_SUFFIX):
        return None
    left = qname[:-len(DOMAIN_SUFFIX)].strip(".")
    parts = left.split(".")
    if len(parts) != 4:
        return None
    ip = ".".join(parts)
    try:
        socket.inet_aton(ip)
        return ip
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Server loop
# ---------------------------------------------------------------------------

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((LISTEN_IP, LISTEN_PORT))
print(f"Listening on {LISTEN_IP}:{LISTEN_PORT} for *.{DOMAIN_SUFFIX}")
print(f"Cloudflare source IPs  →  real A record")
print(f"All other source IPs   →  CNAME {REDIRECT_TARGET}")

while True:
    data, addr = sock.recvfrom(512)
    src_ip = addr[0]

    try:
        req   = DNSRecord.parse(data)
        qname = str(req.q.qname)
        qtype = QTYPE[req.q.qtype]

        reply = DNSRecord(DNSHeader(id=req.header.id, qr=1, aa=1, ra=0), q=req.q)
        ip    = extract_ip(qname)

        if ip and qtype in ("A", "ANY"):
            if is_cf_ip(src_ip):
                reply.add_answer(
                    RR(rname=req.q.qname, rtype=QTYPE.A,
                       rclass=1, ttl=TTL, rdata=A(ip))
                )
            else:
                reply.add_answer(
                    RR(rname=req.q.qname, rtype=QTYPE.CNAME,
                       rclass=1, ttl=TTL, rdata=CNAME(REDIRECT_TARGET))
                )
        else:
            reply.header.rcode = RCODE.NXDOMAIN

        sock.sendto(reply.pack(), addr)

    except Exception:
        pass  # malformed packet — drop silently
