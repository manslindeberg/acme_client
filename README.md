# Demonstration Acme Client

## Summary
This is a demonstration of how an Acme client may be implemented and generally how the ACME protocol
works (RFC8555) to obtain certificates for Let's Encrypt.

**ACME client:** An ACME client which can interact with a standard-conforming ACME server.

**DNS server:** A DNS server which resolves the DNS queries of the ACME server.

**Challenge HTTP server:** An HTTP server to respond to http-01 queries of the ACME server.

**Certificate HTTPS server:** An HTTPS server which uses a certificate obtained by the ACME client.

**Shutdown HTTP server:**  An HTTP server to receive a shutdown signal.


## Features 
- Single & Multi-domain support for HTTP challenges
- Single & Multi-domain support for DNS challenges
- Revocation using HTTP challenges
- Revocation using DNS challenges
- Detects invalid server certificates


## Getting Started
The application is self-contained using the `run` script, for example:
```console
run dns01 --dir https://example.com/dir --record 1.2.3.4 --domain first.example.com --domain example.com
```

or

```console
run http01 --dir https://example.com/dir --record 1.2.3.4 --domain first.example.com --domain example.com
```

depending on using HTTP/DNS type challenges.

