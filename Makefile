DBMATE=dbmate
MIGRATIONS_DIR=db/migrations

.PHONY: migrate new rollback

migrate:
	$(DBMATE) -d $(MIGRATIONS_DIR) up

new:
	$(DBMATE) -d $(MIGRATIONS_DIR) new $(name)

rollback:
	$(DBMATE) -d $(MIGRATIONS_DIR) down