from django.conf.urls import url
from kraut_incident import views

urlpatterns = [
    url(r'^$', views.home, name='home'),
    url(r'^list/$', views.list_incidents, name='list'),
    url(r'^new/$', views.new_incident, name='new'),
    url(r'^incident/(?P<incident_id>\d+)/delete/$', views.delete_incident, name='delete_incident'),
    url(r'^incident/(?P<incident_id>\d+)/view/$', views.view_incident, name='view_incident'),
    url(r'^incident/(?P<incident_id>\d+)/update/header/$', views.update_incident_header, name='update_incident_header'),
    url(r'^incident/(?P<incident_id>\d+)/add/task/$', views.add_task, name='add_task'),
    url(r'^incident/(?P<incident_id>\d+)/add/handler/$', views.add_handler_incident, name='add_handler_incident'),
    url(r'^incident/(?P<incident_id>\d+)/remove/handler/(?P<handler_id>\d+)/$', views.remove_handler_incident, name='remove_handler_incident'),
    url(r'^incident/(?P<incident_id>\d+)/add/comment/$', views.comment_incident, name='comment_incident'),
    url(r'^incident/(?P<incident_id>\d+)/del/comment/(?P<comment_id>\d+)/$', views.delete_comment_incident, name='delete_comment_incident'),
    url(r'^create_contact/$', views.create_contact, name='create_contact'),
    url(r'^create_handler/$', views.create_handler, name='create_handler'),
]

