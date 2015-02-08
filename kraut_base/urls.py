from django.conf.urls import patterns, include, url
from django.contrib import admin


urlpatterns = patterns('',
    #url(r'^', include('kraut_parser.urls')),
    url(r'^api/', include('kraut_api.urls')),
    url(r'^api-auth/', include('rest_framework.urls', namespace='rest_framework')),
    url(r'^admin/', include(admin.site.urls)),
)
