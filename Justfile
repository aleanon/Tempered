default:
    @just --list

compose name="":
    docker compose build {{ name }}
    docker compose down {{ name }}
    docker compose up {{ name }} -d

compose-up:
    docker compose -f compose.dev.yml up -d

compose-down:
    docker compose -f compose.dev.yml down

compose-build:
    docker compose -f compose.dev.yml build

run:
    REDIS_HOST_NAME=127.0.0.1 cd auth-service/ && cargo run
    cd app-service/ && cargo run

log name:
    docker logs project-{{ name }}-1

enter name:
    docker exec -it project-{{ name }}-1 bash

test args="":
    cd {{ args }}/ && cargo nextest run

cleanup-containers:
    docker stop $(docker ps -q)
    docker rm $(docker ps -aq)
    docker volume prune -f

remake-db-containers:
    -docker stop ps-db redis-db
    -docker rm ps-db redis-db
    docker volume prune -f
    docker run --name ps-db -e POSTGRES_PASSWORD=password -p 5432:5432 -d postgres:15.4-alpine
    docker run --name redis-db -p "6379:6379" -d redis:7.0-alpine
    cd auth-service/ && cargo sqlx migrate run

generate-secret length="64":
    openssl rand -base64 {{ length }}

connect:
    ssh root@134.122.65.215
