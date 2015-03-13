# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.contrib import admin
from django.db.models import get_models, get_app

# Register your models here.

for model in get_models(get_app('kraut_intel')):
    admin.site.register(model)
