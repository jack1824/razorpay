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

# One integer reproduces the whole zoo: identities, request streams, and the split the
# trainer uses. Overridable so a second run can be generated without colliding with the
# first's agents.
TRAFFIC_SEED ?= 20260828

# A DIFFERENT seed for evaluation traffic, so the agents measured are not the agents
# trained on. Same seed would mean the eval reported the model's performance on identities
# whose whole request stream it had already learned.
EVAL_SEED ?= 20260901

.PHONY: help up down logs migrate bootstrap-local seed traffic traffic-eval train \
        train-injection explainer traffic-heldout lock-inputs \
        test test-db lint fmt verify eval demo demo-restore clean

help:
	@echo "Dwaar — authorization layer for AI agents that spend money"
	@echo ""
	@echo "  make up        start postgres, redis, api (clean from nothing)"
	@echo "  make down      stop and remove containers"
	@echo "  make logs      tail api logs"
	@echo "  make migrate   apply migrations as the owner role"
	@echo "  make seed      regenerate data/seed/ + .keys/ (deterministic)"
	@echo "  make traffic       bootstrap traffic for TRAINING (gateway must run model-free)"
	@echo "  make traffic-eval  evaluation traffic for MEASURING (gateway runs normally)"
	@echo "  make traffic-heldout  the same PLUS the two held-out archetypes"
	@echo "  make lock-inputs      record bundle hashes + SHAs before a held-out run"
	@echo "  make train     train the risk model from decision_records + the run manifest"
	@echo "  make train-injection   fit the injection detector's weights"
	@echo "  make test      run the full test suite"
	@echo "  make lint      ruff check"
	@echo "  make fmt       ruff format"
	@echo ""
	@echo "  make bootstrap-local   create roles + database on a NON-Docker PostgreSQL,"
	@echo "                         so the DB suite can run without Docker"
	@echo ""
	@echo "  make verify    verify the decision chain"
	@echo "  make eval      the honest numbers (importances, components, FP cost)"
	@echo "  make demo      drive demo beats 1-6 on the timeline's own schedule"
	@echo "  make demo-restore  undo beat 6's tamper"
	@echo "  make explainer     run the async explainer (EXPLAINER_ARGS=--no-model)"

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

# Real signed HTTP against a running local instance. NOT a fixture replay: the gateway
# computes its own features from its own rolling windows, so the training distribution is
# the serving distribution. Start the API first.
#
# Localhost only, enforced in zoo/base.py rather than here.
# BOOTSTRAP traffic, for training. The gateway must be running with NO model loaded:
#
#     DWAAR_MODEL_DIR=/nonexistent uvicorn dwaar.api.app:app --port 8080
#
# A model in the loop decides which requests reach a card, so it decides what payment
# outcomes exist, so it decides what `failure_ratio` looks like. Training on that is
# circular and the trainer refuses it. See FAILURES.md F-031.
traffic:
	$(PY) -m zoo.run --legit 30 --card-tester 4 --budget-breacher 4 --injector 4 \
	  --requests 40 --seed $(TRAFFIC_SEED) \
	  --out data/traffic/bootstrap-$(TRAFFIC_SEED).jsonl

# EVAL traffic, for measuring. The gateway runs as it actually runs — model loaded,
# enforcing. This is the system under test, and it is a different question from the one
# `make traffic` answers.
traffic-eval:
	$(PY) -m zoo.run --legit 30 --card-tester 4 --budget-breacher 4 --injector 4 \
	  --requests 40 --seed $(EVAL_SEED) \
	  --out data/traffic/eval-$(EVAL_SEED).jsonl

# Reads features from decision_records and labels from the run manifest — the two are never
# in one process. Refuses to write a bundle if any single feature separates the archetypes.
train:
	$(PY) -m tools.train_risk --seed $(TRAFFIC_SEED)

# HELD-OUT traffic: the four development archetypes plus `compromised` and `sleeper`.
#
# Those two default to ZERO agents in zoo/run.py, so every run before evaluation day
# generated traffic without them and nothing invoked them by accident. That default is what
# makes their first run against a loaded model actually a first run.
#
# One run, reported. Re-running until the number improves is how a held-out set becomes a
# validation set, and there is no second one.
traffic-heldout:
	$(PY) -m zoo.run --legit 30 --card-tester 4 --budget-breacher 4 --injector 4 \
	  --compromised 4 --sleeper 4 \
	  --requests 40 --seed $(EVAL_SEED) \
	  --out data/traffic/heldout-$(EVAL_SEED).jsonl

# Record what a held-out run is a test OF: bundle hashes, feature ordering, seeds, the
# approved policy version and the SHA of both worktrees. Run BEFORE the traffic.
lock-inputs:
	$(PY) -m tools.lock_inputs

# The injection detector's weights. Fitted over composed templates with the benign side
# drawn from the real product catalogue — including SKU9001, whose name opens with the
# highest-signal injection token there is.
train-injection:
	$(PY) -m tools.train_injection --seed $(TRAFFIC_SEED)

test:
	$(PY) -m pytest -q

test-db:
	$(PY) -m pytest -q -m db

lint:
	$(PY) -m ruff check dwaar tests scripts zoo tools eval

fmt:
	$(PY) -m ruff format dwaar tests scripts zoo tools eval

clean:
	$(COMPOSE) down -v
	rm -rf .pytest_cache .ruff_cache .hypothesis **/__pycache__

# ── The three that were stubs ───────────────────────────────────────────────────────
#
# All three exited 2 until the thing behind them existed, because a stub that exits 0 is
# a green light for something that is not there — the same failure mode as a hardcoded
# metric, and it fails at the worst possible moment. `make demo` was the last one.

# The independent verifier. Read-only connection, no write path, no cooperation from the
# running service required — that is what makes its report worth anything.
verify:
	$(PY) -m dwaar.verify_cli --dsn "$(DATABASE_URL_APP)"

# The honest numbers. Reads decision_records joined to the zoo's run manifests; every
# figure is computed at run time and labelled with what it actually measures.
#
# Prints the top-ten feature importances on EVERY run. That is not decoration: no automated
# check can catch a feature that correlates with how the generator was written (F-030), so
# the only control is a person reading the ranking, and the number goes in front of them.
eval:
	$(PY) -m eval.report

# Drives beats 1-6 from data/seed/timeline.json on its own schedule, so the presenter
# talks rather than clicks. Beat 7 (MCP) stays MANUAL — it is the one worth pausing on.
#
# Every expectation in the timeline is asserted against what the API actually returned, and
# a mismatch is printed loudly and exits non-zero. A runner that echoed the timeline's own
# expectations would be an expensive way to read a JSON file.
#
# Beat 6 tampers a committed record from a superuser connection, which is destructive and
# leaves `make verify` red. That is correct — and `make demo-restore` puts it back.
demo:
	$(PY) -m tools.demo $(DEMO_ARGS)

# Undo beat 6's tamper, by exactly the means it was made.
demo-restore:
	$(PY) -m tools.demo --restore

# The async explainer. Reads decisions off Redis, writes `explanations`, and connects with
# a role that holds SELECT on decision_records and INSERT on explanations and nothing else.
# `--no-model` needs no API key and no network.
explainer:
	$(PY) -m dwaar.explain.worker $(EXPLAINER_ARGS)
