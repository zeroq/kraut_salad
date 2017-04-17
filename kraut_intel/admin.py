# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.contrib import admin
from kraut_intel.models import NamespaceIcon, PackageComment, CampaignComment

# Register your models here.

admin.site.register(NamespaceIcon)
admin.site.register(PackageComment)
admin.site.register(CampaignComment)
