from django.conf.urls import url
from kraut_sharing import views

urlpatterns = [
    url(r'^$', views.home, name='home'),
    url(r'^poll/$', views.poll, name='poll'),
    url(r'^servers/$', views.manage_servers, name='servers'),
    url(r'^server/(?P<server_id>\d+)/delete/$', views.delete_server, name='delete_server'),
]

