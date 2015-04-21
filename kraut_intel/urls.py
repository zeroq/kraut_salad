from django.conf.urls import url
from kraut_intel import views

urlpatterns = [
    url(r'^$', views.home, name='home'),
    url(r'^packages/$', views.packages, name='packages'),
    url(r'^package/(?P<package_id>\d+)/$', views.package, name='package'),
    url(r'^threatactors/$', views.threatactors, name='threatactors'),
    url(r'^campaigns/$', views.campaigns, name='campaigns'),
    url(r'^campaign/(?P<campaign_id>\d+)/$', views.campaign, name='campaign'),
    url(r'^indicators/$', views.indicators, name='indicators'),
    url(r'^indicator/(?P<indicator_id>\d+)/$', views.indicator, name='indicator'),
    url(r'^observables/$', views.observables, name='observables'),
    url(r'^observable/(?P<observable_id>\d+)/$', views.observable, name='observable'),
]

