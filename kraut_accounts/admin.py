# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.contrib import admin
from kraut_accounts.models import UserExtension

# Register your models here.

admin.site.register(UserExtension)
