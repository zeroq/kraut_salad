# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.contrib import admin
from kraut_incident.models import Asset, Incident, Incident_Category, Incident_Status

# Register your models here.

admin.site.register(Asset)
admin.site.register(Incident)
admin.site.register(Incident_Category)
admin.site.register(Incident_Status)
