#!/bin/bash

# TODO: SSLsplit doesn't create a matching cert for IP addresses. Maybe because there is no SNI?
/usr/bin/sslsplit -D \
    -k /home/sslsplit/sslsplit-ca.key \
    -c /home/sslsplit/sslsplit-ca.crt \
    -X /home/sslsplit/traces/sandbox-decrypted-tls-traffic.pcap \
    https 10.10.10.4 443 \
    10.10.10.3 443
