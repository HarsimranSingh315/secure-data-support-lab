# SecureData Support Lab - run `make help`
SHELL := /bin/bash
DC := docker compose
TOOLBOX_IMAGE := securedata-lab/toolbox:0.1
RUN_TOOLBOX := docker run --rm --user "$$(id -u):$$(id -g)" -v "$(CURDIR)":/lab -w /lab --entrypoint "" $(TOOLBOX_IMAGE)
S ?=
R ?= r3
F ?= port 5432
D ?= 20

.PHONY: help up down reset build secrets pki kms-init kms-unseal status seed toolbox alerts \
        scenarios break hint fix capture bundle test lint logs

help:  ## Show this help
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  make %-12s %s\n", $$1, $$2}'

secrets:  ## Generate lab passwords (git-ignored)
	@mkdir -p secrets
	@for f in pg-admin-password app-db-password; do \
	  [ -f secrets/$$f ] || { LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 24 > secrets/$$f; echo "created secrets/$$f"; }; \
	done
	@chmod 600 secrets/* 2>/dev/null || true

build:  ## Build all images
	$(DC) build

pki:  ## Create the CA and server certificates (runs OpenSSL 3 inside the toolbox image)
	@[ -f certs/ca-chain.pem ] && echo "pki: certificates already exist" || { \
	  $(DC) build toolbox && $(RUN_TOOLBOX) ./scripts/pki.sh init; }

up: secrets pki  ## Build and start the whole lab, then initialise or unseal the KMS
	@mkdir -p captures bundles
	$(DC) up -d --build
	@echo "waiting for the database to become healthy..."
	@for i in $$(seq 1 60); do [ "$$($(DC) ps --format '{{.Health}}' db)" = "healthy" ] && break; sleep 2; done
	./scripts/kms.sh init
	@sleep 5; $(MAKE) --no-print-directory status

down:  ## Stop the lab (data is kept)
	$(DC) down

reset:  ## Stop the lab and delete ALL data, certificates and secrets
	$(DC) down -v --remove-orphans
	rm -rf certs/ca certs/*/ certs/.*.backup certs/*.pem secrets/* bundles captures/*.pcap

kms-init:  ## Initialise the KMS (first run) or unseal it
	./scripts/kms.sh init

kms-unseal:  ## Unseal the KMS after a restart
	./scripts/kms.sh unseal

status:  ## Health overview: OSPF, firewall, app, KMS, DAM
	@echo "== OSPF neighbours on r1";  $(DC) exec -T r1 vtysh -c "show ip ospf neighbor" | tail -n +2 || true
	@echo "== Path from Site A to the database"; $(DC) exec -T toolbox traceroute -n -w1 -q1 db.site-b.lab | tail -n +2 || true
	@echo "== App health (via the firewall)"; $(DC) exec -T toolbox curl -s --cacert /lab-certs/ca-chain.pem https://app.site-b.lab:8443/health; echo
	@echo "== KMS"; $(DC) exec -T kms bao status 2>/dev/null | grep -E "Initialized|Sealed" || true
	@echo "== DAM alerts so far"; $(DC) exec -T dam sh -c 'wc -l < /dam/alerts.jsonl 2>/dev/null || echo 0'

seed:  ## Create sample cardholders through the app (card numbers go through the KMS)
	@for c in "Asha Rao|asha@example.lab|4111111111111111" "Ben Lee|ben@example.lab|5555555555554444" "Chloe Roy|chloe@example.lab|378282246310005"; do \
	  IFS='|' read -r n e k <<< "$$c"; \
	  $(DC) exec -T toolbox curl -s --cacert /lab-certs/ca-chain.pem -X POST https://app.site-b.lab:8443/cardholders \
	    -H 'Content-Type: application/json' -d "{\"full_name\":\"$$n\",\"email\":\"$$e\",\"card_number\":\"$$k\"}"; echo; \
	done

toolbox:  ## Open a shell on the Site A support workstation
	$(DC) exec toolbox bash

logs:  ## Follow logs of all services (or one: make logs S=db)
	$(DC) logs -f --tail 50 $(S)

alerts:  ## Show the latest database activity monitoring alerts
	@$(DC) exec -T dam sh -c 'tail -n 20 /dam/alerts.jsonl 2>/dev/null || echo "no alerts yet"'

scenarios:  ## List incident scenarios
	@./scripts/scenario.sh list

break:  ## Inject an incident:   make break S=ospf-mtu
	@./scripts/scenario.sh break $(S)

hint:  ## Get a hint:           make hint S=ospf-mtu
	@./scripts/scenario.sh hint $(S)

fix:  ## Restore the baseline:  make fix S=ospf-mtu
	@./scripts/scenario.sh fix $(S)

capture:  ## Packet capture on a router: make capture R=r3 F='port 5432' D=20 -> captures/*.pcap
	@mkdir -p captures
	@f=captures/$(R)-$$(date +%Y%m%d-%H%M%S).pcap; echo "capturing '$(F)' on $(R) for $(D)s -> $$f"; \
	  $(DC) exec -T $(R) timeout $(D) tcpdump -ni any -U -w - $(F) > $$f 2>/dev/null || true; ls -l $$f

bundle:  ## Collect a redacted support bundle
	./scripts/support-bundle.sh

test:  ## Run unit tests (in a container, nothing to install)
	docker run --rm -v "$(CURDIR)":/lab -w /lab python:3.12-slim sh -c \
	  "apt-get update -qq && apt-get install -y -qq openssl >/dev/null && pip install -q pytest 'psycopg[binary]' && python -m pytest -q services/dam/tests services/app/tests"

lint:  ## Lint shell scripts (in a container)
	docker run --rm -v "$(CURDIR)":/mnt -w /mnt koalaman/shellcheck:stable \
	  scripts/*.sh services/*/*.sh services/common/lab-route
