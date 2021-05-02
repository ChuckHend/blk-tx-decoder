import celery
from celery import Task
from kombu import Exchange, Queue
import logging
import os
CONCURRENCY = os.environ["CONCURRENCY"]

REDIS_PASSWORD=""
REDIS_HOST=os.getenv("REDIS_HOST", "redis")
REDIS_PORT=6379
REDIS_CELERY_DB=0

CELERY_BROKER_URL = (
    f"redis://{REDIS_HOST}:{REDIS_PORT}/{REDIS_CELERY_DB}"
)
logging.info(CELERY_BROKER_URL)
celery_app = celery.Celery(
    "btc_tasks",
    broker=CELERY_BROKER_URL,
    backend=CELERY_BROKER_URL,
)

celery_app.conf.timezone = "America/Chicago"
celery_app.conf.worker_send_tasks_events = True
celery_app.conf.broker_transport_options = {"health_check_interval": 10}
celery_app.conf.worker_concurrency = int(CONCURRENCY)

CELERY_QUEUES = (
    Queue(
        "BLOCKS",
        Exchange("BLOCKS"),
        routing_key='BLOCKS'),
)
celery_app.conf.task_queues = CELERY_QUEUES


class CallbackTask(Task):
    def on_success(self, retval, task_id, args, kwargs):
        # email user?
        pass

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        # set project state to "ERROR"
        pass

logging.info(celery_app)