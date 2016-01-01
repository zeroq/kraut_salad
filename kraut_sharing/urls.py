from django.conf.urls import url
from kraut_sharing import views

urlpatterns = [
    url(r'^$', views.home, name='home'),
    url(r'^poll/$', views.poll, name='poll'),
    url(r'^collections/$', views.list_collections, name='collections'),
    url(r'^collections/(?P<collection_id>\d+)/poll/$', views.poll_now, name='poll_now'),
    url(r'^servers/$', views.manage_servers, name='servers'),
    url(r'^server/(?P<server_id>\d+)/delete/$', views.delete_server, name='delete_server'),
    url(r'^server/(?P<server_id>\d+)/refresh/$', views.refresh_collection, name='refresh_collection'),
]

