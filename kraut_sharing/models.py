# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.db import models

# Create your models here.

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

    def __unicode__(self):
        return "%s (%s://%s:%i%s)" % (self.name, self.protocol, self.host, self.port, self.path)
