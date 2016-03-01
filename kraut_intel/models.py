# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.db import models
from django.contrib.auth.models import User

from kraut_parser.models import Package

# Create your models here.

class NamespaceIcon(models.Model):
    namespace = models.CharField(max_length=255, unique=True)
    icon = models.CharField(max_length=255)

    def __unicode__(self):
        return u"%s (%s)" % (self.namespace, self.icon)

class PackageComment(models.Model):
    ctext = models.TextField()
    author = models.ForeignKey(User)
    creation_time = models.DateTimeField(auto_now_add=True)
    package_reference = models.ForeignKey(Package)

    #def __unicode__(self):
    #    return u"%s" % (self.creation_time.strftime("%Y-%m-%d %H:%M:%S"))

