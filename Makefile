include .env
MIGRATION_PATH = ./cmd/migrate/migrations

create_migrations:
	sqlx migrate add -r init
migrate-up:
	sqlx migrate run --database-url "postgres://${DB_USER}:${PASSWD}@${HOST}:${PORT}/${DB_NAME}?sslmode=disable"
migrate-down:
	sqlx migrate revert --database-url "postgres://${DB_USER}:${PASSWD}@${HOST}:${PORT}/${DB_NAME}?sslmode=disable"
stop_containers:
	@echo "Stopping other docker containers"
	@if test -n "$$(docker ps -q)"; then \
		echo "Found and stopped containers"; \
		docker stop $$(docker ps -q); \
	else \
		echo "No containers running..."; \
	fi

create_container:
	docker run --name ${DB_DOCKER_CONTAINER} -p 5436:5432 -e POSTGRES_USER=${DB_USER} -e POSTGRES_PASSWORD=${PASSWD} -d postgres:16-alpine

create_db:
	docker exec -it ${DB_DOCKER_CONTAINER} createdb --username=${DB_USER} --owner=${DB_USER} ${DB_NAME}

start_container:
	docker start ${DB_DOCKER_CONTAINER}

build:
	if [ -f "${BINARY}" ]; then \
		rm ${BINARY}; \
		echo "Deleted ${BINARY}"; \
	fi
	@echo "Building binary..."
	go build -o ${BINARY} cmd/main.go

run: build
	./${BINARY}
#@@echo "api started..."

stop:
	@echo "stopping server..."
	@-pkill -SIGTERM -f "./${BINARY}"
	@echo "server stopped..."

test:
	@go test -v ./...
