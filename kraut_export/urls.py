from django.conf.urls import url
from kraut_export import views

urlpatterns = [
    url(r'^observable/(?P<pk>[0-9]+)/cybox/$', views.cybox_observable, name='cybox_observable'),
]

