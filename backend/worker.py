from redis import Redis
from rq import Queue
from rq.worker import SimpleWorker
from rq.timeouts import BaseDeathPenalty

from app import create_app
from app.config import Config

class WindowsDeathPenalty(BaseDeathPenalty):
    def setup_death_penalty(self):
        pass
    def cancel_death_penalty(self):
        pass


class WindowsWorker(SimpleWorker):
    death_penalty_class = WindowsDeathPenalty


app = create_app()
redis_conn = Redis.from_url(app.config['REDIS_URL'])
queue = Queue(connection=redis_conn)

with app.app_context():
    worker = WindowsWorker([queue], connection=redis_conn)
    worker.work()
