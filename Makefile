# Don't ask me what is going in this Makefile
include .env
MIGRATION_PATH = ./cmd/migrate/migrations


create_container:
	docker run --name ${DB_DOCKER_CONTAINER} -p 5436:5432 -e POSTGRES_USER=${DB_USER} -e POSTGRES_PASSWORD=${PASSWD} -d postgres:16-alpine

create_db:
	docker exec -it ${DB_DOCKER_CONTAINER} createdb --username=${DB_USER} --owner=${DB_USER} ${DB_NAME}

start_container:
	docker start ${DB_DOCKER_CONTAINER}

build:
	@mkdir -p bin
	if [ -f "bin/${BINARY}" ]; then \
		rm bin/${BINARY}; \
		echo "Deleted old binary"; \
	fi
	@echo "Building binary..."
	go build -o bin/${BINARY} cmd/main.go

run: build
	@echo "Starting API..."
	@bin/${BINARY}
stop:
	@echo "stopping server..."
	@-pkill -SIGTERM -f "./${BINARY}"
	@echo "server stopped..."

test:
	@go test -v ./...

create_migrations:
	sqlx migrate add -r $(filter-out $@,$(MAKECMDGOALS))

# This line prevents make from trying to interpret the arguments as targets
%:
	@:
migrate-up:
	sqlx migrate run --database-url "${DB_URL}"
migrate-down:
	sqlx migrate revert --database-url "${DB_URL}"
stop_containers:
	@echo "Stopping other docker containers"
	@if test -n "$$(docker ps -q)"; then \
		echo "Found and stopped containers"; \
		docker stop $$(docker ps -q); \
	else \
		echo "No containers running..."; \
	fi
