from django.conf.urls import url
from rest_framework.urlpatterns import format_suffix_patterns
from kraut_parser import views

urlpatterns = [
    url(r'^indicators/$', views.indicator_list),
    url(r'^indicators/(?P<pk>[0-9]+)/$', views.indicator_detail),
    url(r'^observables/$', views.observable_list),
]

urlpatterns = format_suffix_patterns(urlpatterns)
