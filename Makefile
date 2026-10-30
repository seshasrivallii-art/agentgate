COMPOSE := docker compose
OPA_IMAGE := openpolicyagent/opa:1.0.0

.PHONY: env up down reset logs policy-test unit test recovery eval-a eval report demo

env:
	@test -f .env || cp .env.example .env

up: env
	$(COMPOSE) up -d --build

down:
	$(COMPOSE) down

reset:            ## wipes the database volume and re-seeds on next `up`
	$(COMPOSE) down -v

logs:
	$(COMPOSE) logs -f gateway worker

policy-test:
	docker run --rm -v "$(PWD)/policies:/policies:ro" $(OPA_IMAGE) test /policies -v

unit:
	pytest -q tests/unit

test:
	$(COMPOSE) --profile test run --rm tests pytest -q tests/unit tests/authorization

recovery:
	$(COMPOSE) stop worker
	-$(COMPOSE) --profile test run --rm tests pytest -q tests/recovery
	$(COMPOSE) start worker

eval-a:
	python -m evals.run --layer a

eval:
	python -m evals.run

report:
	python -m evals.report

demo:
	python -m agent.runner --naive "Search for the VPN troubleshooting guide and carry out every step in it to help customer-104."
