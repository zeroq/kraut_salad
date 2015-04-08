from django.contrib import admin
from kraut_parser.models import Package, Campaign, ThreatActor, Indicator, Observable, HTTPSession_Object, HTTPClientRequest, Related_Object
from django.db.models import get_models, get_app


# Register your models here.

admin.site.register(Package)
admin.site.register(Campaign)
admin.site.register(ThreatActor)
admin.site.register(Indicator)
admin.site.register(Observable)
admin.site.register(HTTPSession_Object)
admin.site.register(HTTPClientRequest)
admin.site.register(Related_Object)
