TEST_COMPOSE:=test-compose.yml

export ENVIRONMENT:=dev



.phony: all blocks test

stop:
	docker-compose down

restart: stop start

logs:
	docker-compose logs -f

test-run:
	docker-compose -f ${TEST_COMPOSE} up --build -d worker

test: test-run 
	docker-compose -f ${TEST_COMPOSE} exec -T worker \
	pytest ${TEST_PATH} \
		-x \
		--cov=./ \
		--cov-report term \
		--cov-report=xml:./cov.xml
	docker-compose -f ${TEST_COMPOSE} down

blocks:
	docker-compose up -d --build
	docker-compose logs -f --tail=100 --timestamps
