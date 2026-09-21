SHELL := /bin/bash

.PHONY: install cert containers run analyze
.SILENT:

# TODO: Put all scripts into scripts/
install:
# TODO: Should we create a VM image with all the necessary tools?
	sudo dnf install -y suricata
	sudo suricata-update
	sudo rpm --import https://falco.org/repo/falcosecurity-packages.asc
	sudo curl -o /etc/yum.repos.d/falcosecurity.repo https://falco.org/repo/falcosecurity-rpm.repo
	sudo yum install -y falco
	sudo systemctl disable falco  # We don't need the service, just the tool.

cert:
	openssl genrsa -out sslsplit-ca.key 4096
	openssl req -new -x509 -sha256 -days 365 \
		-key sslsplit-ca.key \
		-out sslsplit-ca.crt \
		-subj "/CN=ABS CloudOps Sandbox CA/OU=ABS CloudOps/O=Allianz Technology/C=DE"

containers:
# TODO: Can we build the images with podman compose?
	podman build -t inetsim -f Dockerfile-inetsim .
	podman build -t sslsplit -f Dockerfile-sslsplit .
	podman build -t sandbox -f Dockerfile-sandbox .

run:
	./run-sandbox.sh

analyze:
	./run-analysis.sh
