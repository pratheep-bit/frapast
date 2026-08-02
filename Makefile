SITE_NAME ?= security.localhost
BUG ?=
COMPOSE ?= docker compose
BENCH_ROOT ?= /home/frappe/bench-state
BENCH_DIR ?= $(BENCH_ROOT)/frappe-bench
BENCH = $(COMPOSE) exec bench bash -lc

.PHONY: site-new site-seed site-serve repro teardown test lint logs

site-new:
	$(COMPOSE) up -d --wait mariadb redis-cache bench worker scheduler
	$(BENCH) 'mkdir -p $(BENCH_ROOT) && sudo chown -R frappe:frappe $(BENCH_ROOT)'
	$(BENCH) 'if [ ! -d $(BENCH_DIR)/apps/frappe ]; then rm -rf $(BENCH_DIR) && bench init --skip-redis-config-generation --skip-assets --frappe-branch develop $(BENCH_DIR); fi'
	$(BENCH) 'cd $(BENCH_DIR) && bench set-mariadb-host mariadb'
	$(BENCH) 'cd $(BENCH_DIR) && bench config set-common-config -c redis_cache "'\''redis://redis-cache:6379'\''" -c redis_queue "'\''redis://redis-cache:6379'\''" -c redis_socketio "'\''redis://redis-cache:6379'\''"'
	$(BENCH) 'cd $(BENCH_DIR) && if [ ! -f sites/$(SITE_NAME)/site_config.json ]; then bench new-site $(SITE_NAME) --mariadb-root-password admin --admin-password admin --no-mariadb-socket; fi'
	$(BENCH) 'test -f $(BENCH_DIR)/sites/$(SITE_NAME)/site_config.json'

site-seed:
	$(BENCH) 'test -f $(BENCH_DIR)/sites/$(SITE_NAME)/site_config.json'
	$(BENCH) 'cd $(BENCH_DIR) && bench --site $(SITE_NAME) execute frappe.get_installed_apps'
	$(BENCH) 'cd $(BENCH_DIR) && bench --site $(SITE_NAME) execute frappe.get_all --kwargs "{\"doctype\":\"DocType\",\"limit\":1}"'

site-serve:
	$(COMPOSE) up -d --wait bench mariadb redis-cache
	$(BENCH) 'cd $(BENCH_DIR) && if ! pgrep -f "bench serve --port 8000" >/dev/null; then nohup bench serve --port 8000 >/tmp/frappe-security-serve.log 2>&1 & fi'
	@for attempt in 1 2 3 4 5 6 7 8 9 10; do \
		if curl --silent --show-error --max-time 2 -H "Host: $(SITE_NAME)" http://127.0.0.1:8000/api/method/ping >/dev/null; then exit 0; fi; \
		sleep 1; \
	done; \
	echo "Frappe HTTP server did not become ready"; exit 1

repro:
	@if [ -z "$(BUG)" ]; then echo "Usage: make repro BUG=FR-PERM-001-0001"; exit 2; fi
	$(BENCH) 'cd $(BENCH_DIR) && if [ -x /workspace/runtime/reproducers/$(BUG).sh ]; then /workspace/runtime/reproducers/$(BUG).sh; else echo "No reproducer for $(BUG)"; exit 3; fi'

teardown:
	$(COMPOSE) down --volumes --remove-orphans

test:
	$(COMPOSE) up -d --wait mariadb redis-cache bench
	$(BENCH) 'cd /workspace && python -m pytest tests'

lint:
	$(COMPOSE) up -d --wait bench
	$(BENCH) 'cd /workspace && pre-commit run --all-files'

logs:
	$(COMPOSE) logs --tail=200
