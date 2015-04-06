from django.contrib import admin
from kraut_parser.models import Package, Campaign, ThreatActor, Indicator, Observable
from django.db.models import get_models, get_app


# Register your models here.

admin.site.register(Package)
admin.site.register(Campaign)
admin.site.register(ThreatActor)
admin.site.register(Indicator)
admin.site.register(Observable)
