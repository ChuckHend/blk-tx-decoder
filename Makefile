export ENVIRONMENT:=dev

.phony: blocks

stop:
	docker-compose down

restart: stop start

logs:
	docker-compose logs -f

test: run-test
	ENVIRONMENT=test docker-compose -f test-compose.yml exec -T loader \
	pytest ${TEST_PATH} \
		-x \
		--cov=collector \
		--cov-report term \
		--cov-report=xml:./cov.xml
	ENVIRONMENT=test docker-compose -f test-compose.yml down

blocks:
	docker-compose up -d --build
	docker-compose logs -f --tail=100 --timestamps
