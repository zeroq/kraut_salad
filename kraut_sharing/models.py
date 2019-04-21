# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.db import models

# Create your models here.

class OSINT_Feed(models.Model):
    creation_time = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=255, help_text="""Name/Identifier""")
    url = models.CharField(max_length=2014, help_text="""URL for feed""")
    last_pull = models.DateTimeField(blank=True, null=True)
    namespace = models.CharField(max_length=255, default='nospace')
    source = models.CharField(max_length=255, default='unknown')

    def __unicode__(self):
        return u"%s" % (self.name)

class TAXII_Remote_Collection(models.Model):
    creation_time = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    name = models.CharField(max_length=255, help_text="""name of the collection""", unique=True)
    begin_timestamp = models.DateTimeField(blank=True, null=True)
    end_timestamp = models.DateTimeField(blank=True, null=True)
    server = models.ForeignKey("TAXII_Remote_Server", on_delete=models.CASCADE)
    subscribed = models.BooleanField(default=False)
    collection_type = models.CharField(max_length=255, default="DATA-FEED")
    poll_period = models.IntegerField(default=24, help_text="""poll period in hours (e.g. 24 = every 24 hours)""")

    def __unicode__(self):
        return u"%s" % (self.name)

class TAXII_Remote_Server(models.Model):
    creation_time = models.DateTimeField(auto_now_add=True)
    name = models.CharField(max_length=255, help_text="""Name/Identifier""")
    host = models.CharField(max_length=255, help_text="""Hostname or IP address""")
    port = models.IntegerField(help_text="""Remote port""", default=80)
    protocol = models.CharField(max_length=5, help_text="""Protocol to use""", default="http")
    path = models.CharField(max_length=255, help_text="""Path to service""")
    version = models.CharField(max_length=5, help_text="""TAXII version to use""", default="1.1")
    auth_type = models.IntegerField(default=0, help_text="""Authentication to use""")
    last_discovery = models.DateTimeField(blank=True, null=True)
    # TODO: fields for authentication (foreign key)
    # TODO: proxy configuration

    def get_url(self):
        return "%s://%s:%i%s" % (self.protocol, self.host, self.port, self.path)

    def __unicode__(self):
        return u"%s (%s://%s:%i%s)" % (self.name, self.protocol, self.host, self.port, self.path)

    class Meta:
        unique_together = (("name", "host", "port", "protocol", "path"),)
