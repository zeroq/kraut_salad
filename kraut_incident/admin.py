# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.contrib import admin
from kraut_incident.models import Asset, Incident

# Register your models here.

admin.site.register(Asset)
admin.site.register(Incident)
