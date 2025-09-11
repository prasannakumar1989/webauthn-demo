DBMATE=dbmate
MIGRATIONS_DIR=db/migrations
SQLC=sqlc

.PHONY: migrate new rollback sqlc-generate

migrate:
	$(DBMATE) -d $(MIGRATIONS_DIR) up

new:
	$(DBMATE) -d $(MIGRATIONS_DIR) new $(name)

rollback:
	$(DBMATE) -d $(MIGRATIONS_DIR) down

sqlc-generate:
	$(SQLC) generate