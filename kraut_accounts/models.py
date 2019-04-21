# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.db import models
from django.contrib.auth.models import User

from kraut_parser.models import Namespace

# Create your models here.

class UserExtension(models.Model):
    user = models.OneToOneField(User, primary_key=True, on_delete=models.CASCADE)
    icon = models.CharField(max_length=100, default="ns_icon/octalpus.png")
    namespaces = models.ManyToManyField(Namespace, blank=True)
