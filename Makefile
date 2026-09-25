SHELL := /bin/bash

.PHONY: install cert containers run analyze
.SILENT:

install:
# TODO: Should we create a VM image with all the necessary tools?
	sudo dnf install -y suricata
	sudo suricata-update
	sudo rpm --import https://falco.org/repo/falcosecurity-packages.asc
	sudo curl -o /etc/yum.repos.d/falcosecurity.repo https://falco.org/repo/falcosecurity-rpm.repo
	sudo yum install -y falco
	sudo systemctl disable falco  # We don't need the service, just the tool.

certs:
	mkdir -p run/
	openssl genrsa -out run/sslsplit-ca.key 4096
	openssl req -new -x509 -sha256 -days 365 \
		-key run/sslsplit-ca.key \
		-out run/sslsplit-ca.crt \
		-subj "/CN=ABS CloudOps Sandbox CA/OU=ABS CloudOps/O=Allianz Technology/C=DE"
# Adapt the list of required root CA certs and the paths to the environment where the sandbox runs.
	cp /etc/pki/ca-trust/source/anchors/Allianz_Root_CA_IV.pem run/Allianz_Root_CA_IV.crt
	cp /etc/pki/ca-trust/source/anchors/Allianz_Infrastructure_CA_VI.pem run/Allianz_Infrastructure_CA_VI.crt
	cp /etc/pki/ca-trust/source/anchors/Zscaler_Root_CA.pem run/Zscaler_Root_CA.crt

containers:
# TODO: Can we build the images with podman compose?
	podman build -t inetsim -f Dockerfile-inetsim .
	podman build -t sslsplit -f Dockerfile-sslsplit .
	podman build -t sandbox -f Dockerfile-sandbox .

run:
	scripts/run-sandbox.sh

analyze:
	scripts/run-analysis.sh
