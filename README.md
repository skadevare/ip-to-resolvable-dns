
# DNS IP Resolver

A tiny authoritative DNS responder that resolves IP addresses embedded in DNS names.

For example, a DNS query for:

```text
8.8.8.8.your.domain.xyz
```

returns:

```text
8.8.8.8
```

This can be useful for testing DNS-based routing, tunneling experiments, debugging resolvers, or creating predictable DNS responses for arbitrary IPv4 addresses.

## How it works

The script listens for UDP DNS queries on port `53`. When it receives a query ending in your configured domain suffix, it extracts the left-hand IPv4 address and returns it as an `A` record.

Expected query format:

```text
X.X.X.X.your.domain.xyz.
```

Example:

```text
1.1.1.1.your.domain.xyz.
```

# V2 now supports whitelisting of DNS
Place your the domain that you want to mask the ip as by changing the `REDIRECT_TARGET` in the script.
