# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.db import models

# Create your models here.

class NamespaceIcon(models.Model):
    namespace = models.CharField(max_length=255, unique=True)
    icon = models.CharField(max_length=255)

    def __unicode__(self):
        return u"%s (%s)" % (self.namespace, self.icon)
