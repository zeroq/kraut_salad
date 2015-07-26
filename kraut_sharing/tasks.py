# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from celery import Celery

app = Celery(broker='amqp://')

@app.task(ignore_result=True)
def taxii_discovery(url):
    print("testing celery ... %s" % (url))
    return True
