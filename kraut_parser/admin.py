from django.contrib import admin
from kraut_parser.models import Package, Campaign, ThreatActor, Indicator, Observable, HTTPSession_Object, HTTPClientRequest, Related_Object, ObservableComposition, Package_Intent, Package_Reference, TA_Types, TA_Roles, TA_Alias, DNSQuery_Object, DNSQuestion, URI_Object, File_Object, TTP, RelatedTTP, MalwareInstance, MalwareInstanceNames, MalwareInstanceTypes
from kraut_parser.models import AttackPattern, Link_Object, Namespace
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
admin.site.register(ObservableComposition)
admin.site.register(Package_Intent)
admin.site.register(Package_Reference)
admin.site.register(TA_Types)
admin.site.register(TA_Roles)
admin.site.register(TA_Alias)
admin.site.register(DNSQuery_Object)
admin.site.register(DNSQuestion)
admin.site.register(URI_Object)
admin.site.register(File_Object)
admin.site.register(TTP)
admin.site.register(RelatedTTP)
admin.site.register(MalwareInstance)
admin.site.register(MalwareInstanceNames)
admin.site.register(MalwareInstanceTypes)
admin.site.register(AttackPattern)
admin.site.register(Link_Object)
admin.site.register(Namespace)
