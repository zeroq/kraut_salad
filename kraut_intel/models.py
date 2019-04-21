# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.db import models
from django.contrib.auth.models import User

from kraut_parser.models import Package, ThreatActor, Campaign, TTP, Indicator, Observable

# Create your models here.

class NamespaceIcon(models.Model):
    namespace = models.CharField(max_length=255, unique=True)
    icon = models.CharField(max_length=255)

    def __unicode__(self):
        return u"%s (%s)" % (self.namespace, self.icon)

class PackageComment(models.Model):
    ctext = models.TextField()
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    creation_time = models.DateTimeField(auto_now_add=True)
    package_reference = models.ForeignKey(Package, on_delete=models.CASCADE)


class ThreatActorComment(models.Model):
    ctext = models.TextField()
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    creation_time = models.DateTimeField(auto_now_add=True)
    actor_reference = models.ForeignKey(ThreatActor, on_delete=models.CASCADE)

class CampaignComment(models.Model):
    ctext = models.TextField()
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    creation_time = models.DateTimeField(auto_now_add=True)
    campaign_reference = models.ForeignKey(Campaign, on_delete=models.CASCADE)

class TTPComment(models.Model):
    ctext = models.TextField()
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    creation_time = models.DateTimeField(auto_now_add=True)
    ttp_reference = models.ForeignKey(TTP, on_delete=models.CASCADE)

class IndicatorComment(models.Model):
    ctext = models.TextField()
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    creation_time = models.DateTimeField(auto_now_add=True)
    indicator_reference = models.ForeignKey(Indicator, on_delete=models.CASCADE)

class ObservableComment(models.Model):
    ctext = models.TextField()
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    creation_time = models.DateTimeField(auto_now_add=True)
    observable_reference = models.ForeignKey(Observable, on_delete=models.CASCADE)
