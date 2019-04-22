from django.conf.urls import include, url
from django.contrib import admin

from kraut_base import views

app_name = 'kraut_base'

urlpatterns = [
    url(r'^$', views.home, name='home'),
    url(r'^incidents/', include(('kraut_incident.urls', 'incidents'), namespace='incidents')),
    url(r'^intel/', include(('kraut_intel.urls', 'intel'), namespace='intel')),
    url(r'^sharing/', include(('kraut_sharing.urls', 'sharing'), namespace='sharing')),
    url(r'^export/', include(('kraut_export.urls', 'export'), namespace='export')),
    url(r'^accounts/', include(('kraut_accounts.urls', 'accounts'), namespace='accounts')),
    url(r'^api/', include(('kraut_api.urls', 'api'), namespace='api')),
    url(r'^api-auth/', include(('rest_framework.urls', 'rest_framework'), namespace='rest_framework')),
    url(r'^search/', include(('kraut_search.urls', 'search'), namespace='search')),
    url(r'^admin/', admin.site.urls),
]
