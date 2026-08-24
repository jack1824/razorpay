.DEFAULT_GOAL := help
SHELL := /bin/bash

COMPOSE ?= docker compose

# Prefer the project venv when one exists, so `make test` does not silently run against a
# system interpreter that has none of the dependencies installed.
PY ?= $(shell if [ -x .venv/bin/python ]; then echo .venv/bin/python; else echo python3; fi)

# Local test DSNs. Inside Compose the host is `postgres`; from the host it is localhost.
export DATABASE_URL_MIGRATE ?= postgresql://dwaar_owner:owner_pw@localhost:5432/dwaar
export DATABASE_URL_APP     ?= postgresql://dwaar_app:app_pw@localhost:5432/dwaar
export DATABASE_URL_SUPERUSER ?= postgresql://postgres:postgres_pw@localhost:5432/dwaar

.PHONY: help up down logs migrate bootstrap-local seed test test-db lint fmt verify eval demo clean

help:
	@echo "Dwaar — authorization layer for AI agents that spend money"
	@echo ""
	@echo "  make up        start postgres, redis, api (clean from nothing)"
	@echo "  make down      stop and remove containers"
	@echo "  make logs      tail api logs"
	@echo "  make migrate   apply migrations as the owner role"
	@echo "  make seed      regenerate data/seed/ + .keys/ (deterministic)"
	@echo "  make test      run the full test suite"
	@echo "  make lint      ruff check"
	@echo "  make fmt       ruff format"
	@echo ""
	@echo "  make bootstrap-local   create roles + database on a NON-Docker PostgreSQL,"
	@echo "                         so the DB suite can run without Docker"
	@echo ""
	@echo "  make verify    verify the decision chain      [day 4  — not implemented]"
	@echo "  make eval      compute the evaluation table   [day 12 — not implemented]"
	@echo "  make demo      drive the demo beats           [day 11 — not implemented]"

up:
	$(COMPOSE) up -d --build
	@echo "waiting for api to become healthy..."
	@for i in $$(seq 1 60); do \
	  status=$$(docker inspect -f '{{.State.Health.Status}}' dwaar-api 2>/dev/null || echo starting); \
	  if [ "$$status" = "healthy" ]; then echo "api healthy"; \
	    curl -fsS http://localhost:8080/health && echo && exit 0; fi; \
	  sleep 2; \
	done; \
	echo "api did not become healthy in time"; $(COMPOSE) logs api; exit 1

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f api

migrate:
	$(PY) -m dwaar.db.migrate "$(DATABASE_URL_MIGRATE)"

# Same role setup as scripts/init-db/01-roles.sh, for a PostgreSQL you already have.
# The two paths must never disagree that dwaar_app owns nothing — that is the control.
bootstrap-local:
	./scripts/init-db/local-bootstrap.sh
	$(MAKE) migrate

# Regenerate data/seed/ and .keys/. Deterministic: same seed, byte-identical output.
# If `make test` reports data/seed/ differs from generator output, someone edited a
# fixture instead of the generator. Regenerate; never hand-edit.
seed:
	$(PY) -m tools.gen_seed --out data/seed --seed 20260905

test:
	$(PY) -m pytest -q

test-db:
	$(PY) -m pytest -q -m db

lint:
	$(PY) -m ruff check dwaar tests scripts

fmt:
	$(PY) -m ruff format dwaar tests scripts

clean:
	$(COMPOSE) down -v
	rm -rf .pytest_cache .ruff_cache .hypothesis **/__pycache__

# ── Not yet implemented ─────────────────────────────────────────────────────────────
#
# These exit 2, deliberately. A stub that exits 0 is a green light for something that
# does not exist — the same failure mode as a hardcoded metric, and it fails at the
# worst possible moment. Non-zero until the thing is real.

# The independent verifier. Read-only connection, no write path, no cooperation from the
# running service required — that is what makes its report worth anything.
verify:
	$(PY) -m dwaar.verify_cli --dsn "$(DATABASE_URL_APP)"

eval:
	@echo "make eval — NOT IMPLEMENTED"
	@echo ""
	@echo "  Lands day 12 (docs/strategy/BUILD_PLAN.md). Depends on the risk model (day 7)"
	@echo "  and the agent zoo (day 8), including the two held-out archetypes."
	@echo "  Every number it prints will be computed at run time. Rule 4."
	@exit 2

demo:
	@echo "make demo — NOT IMPLEMENTED"
	@echo ""
	@echo "  Lands day 11 (docs/strategy/BUILD_PLAN.md). Depends on the console and a"
	@echo "  working authorize path (day 6)."
	@echo "  Blocked on FAILURES.md F-006: the corrected demo timeline has not arrived."
	@exit 2
