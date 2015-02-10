from django.conf.urls import url
from kraut_intel import views

urlpatterns = [
    url(r'^$', views.home, name='home'),
    url(r'^packages/$', views.packages, name='packages'),
    url(r'^threatactors/$', views.threatactors, name='threatactors'),
]

