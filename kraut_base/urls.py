from django.conf.urls import patterns, include, url
from django.contrib import admin

from kraut_base import views

urlpatterns = patterns('',
    url(r'^$', views.home, name='home'),
    url(r'^incidents/', include('kraut_incident.urls', namespace='incidents')),
    url(r'^intel/', include('kraut_intel.urls', namespace='intel')),
    url(r'^sharing/', include('kraut_sharing.urls', namespace='sharing')),
    url(r'^export/', include('kraut_export.urls', namespace='export')),
    url(r'^api/', include('kraut_api.urls', namespace='api')),
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    url(r'^admin/', include(admin.site.urls)),
)
