# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.db import models
from django.contrib.auth.models import User

import random

# Create your helper function here.

def random_incident_number():
    """Generate a random incident number
    """
    random.seed()
    return random.randint(1000, 9999999999)

# Create your models here.

class Handler(models.Model):
    """Describe an incident handler person
    """
    firstname = models.CharField(max_length=255)
    lastname = models.CharField(max_length=255)
    phone = models.CharField(max_length=255, blank=True)
    email = models.EmailField(max_length=255)
    description = models.TextField(null=True, blank=True)

    class Meta:
        unique_together = (("firstname", "lastname", "email"),)

class Contact(models.Model):
    """Describe a contact person
    """
    firstname = models.CharField(max_length=255)
    lastname = models.CharField(max_length=255)
    phone = models.CharField(max_length=255, blank=True)
    email = models.EmailField(max_length=255)
    description = models.TextField(null=True, blank=True)

    class Meta:
        unique_together = (("firstname", "lastname", "email"),)

class TemplateTask(models.Model):
    """Describe a template for a task to attach to an incident
    """
    name = models.CharField(max_length=255, default="Template Task")
    description = models.TextField(null=True, blank=True, default="Task Description")

class Task(models.Model):
    """Describe a task to be performed
    """
    name = models.CharField(max_length=255, default="Yet another task")
    description = models.TextField(null=True, blank=True)
    creation_time = models.DateTimeField(auto_now_add=True)
    finish_time = models.DateTimeField(null=True, blank=True)
    status_choices = (
                ('op', 'Open'),
                ('do', 'Done'),
                ('ab', 'Aborted'),
            )
    status = models.CharField(max_length=2, choices=status_choices, default='op')
    responsible = models.ManyToManyField(Contact, blank=True)

    class Meta:
        ordering = ['-status']

class Account(models.Model):
    """Describe an account
    """
    name = models.CharField(max_length=255)
    domain = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)
    responsible = models.ManyToManyField(Contact, blank=True)
    status_choices = (
                ('cl', 'Clean'),
                ('co', 'Compromised'),
            )
    status = models.CharField(max_length=2, choices=status_choices, default='cl')

    class Meta:
        unique_together = (("name", "domain"),)

class Asset_Status(models.Model):
    """Describe the current status of an asset
    Prefilled with data
    """
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(null=True, blank=True)

    def __unicode__(self):
        return u"%s" % (self.name)

class Asset_IP(models.Model):
    """Describe an IP address of an affected asset
    """
    ip = models.GenericIPAddressField(unique=True)

class Asset_Attacker_Activity(models.Model):
    """Describe time and activity of an attacker on an affected asset
    """
    activity_time = models.DateTimeField()
    activity = models.TextField()

class Asset_Network_Connection(models.Model):
    """Describe a network connection between two assets
    """
    connection_time = models.DateTimeField()
    description = models.TextField(null=True, blank=True)
    asset_one_id = models.IntegerField()
    asset_two_id = models.IntegerField()

    class Meta:
        unique_together = (("asset_one_id", "asset_one_id", "connection_time"),)

class Asset(models.Model):
    """Describe an asset and its role in an incident
    """
    asset_type = models.CharField(max_length=255, default="Unknown Type")
    description = models.TextField(null=True, blank=True)
    status = models.ForeignKey(Asset_Status, on_delete=models.CASCADE)
    hostname = models.CharField(max_length=255, null=True, blank=True)
    domain = models.CharField(max_length=255, null=True, blank=True)
    ip_addresses = models.ManyToManyField(Asset_IP, blank=True)
    contacts = models.ManyToManyField(Contact, blank=True)
    activities = models.ManyToManyField(Asset_Attacker_Activity, blank=True)
    tasks = models.ManyToManyField(Task, blank=True)
    accounts = models.ManyToManyField(Account, blank=True)

class Incident_Status(models.Model):
    """Describe the status of an incident
    Prefilled with data
    """
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(null=True, blank=True)

    def __unicode__(self):
        return u"%s" % (self.name)

class Incident_Category(models.Model):
    """Describe the category of an incident
    Prefilled with data
    """
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(null=True, blank=True)

    def __unicode__(self):
        return u"%s" % (self.name)

class Incident(models.Model):
    """Describe a security incident
    """
    incident_number = models.IntegerField(unique=True, default=random_incident_number)
    title = models.CharField(max_length=255, default="Unnamed Incident")
    description = models.TextField(null=True, blank=True)
    creation_time = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    status = models.ForeignKey(Incident_Status, on_delete=models.CASCADE)
    category = models.ForeignKey(Incident_Category, on_delete=models.CASCADE)
    affected_assets = models.ManyToManyField(Asset, blank=True)
    tasks = models.ManyToManyField(Task, blank=True)
    incident_handler = models.ManyToManyField(Handler, blank=True, related_name="incident_handler")
    contacts = models.ManyToManyField(Contact, blank=True, related_name="contacts")
    severity_choices = (
                ('h', 'High'),
                ('m', 'Medium'),
                ('l', 'Low'),
            )
    severity = models.CharField(max_length=2, choices=severity_choices, default='m')

    def __unicode__(self):
        return u"%s" % (self.title)


class IncidentComment(models.Model):
    ctext = models.TextField()
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    creation_time = models.DateTimeField(auto_now_add=True)
    incident_reference = models.ForeignKey(Incident, on_delete=models.CASCADE)
