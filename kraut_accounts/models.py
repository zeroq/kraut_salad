# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.db import models
from django.contrib.auth.models import User

# Create your models here.

class UserExtension(models.Model):
    user = models.OneToOneField(User, primary_key=True)
    icon = models.CharField(max_length=100, default="ns_icon/octalpus.png")
