from django.conf.urls import url
from kraut_intel import views

urlpatterns = [
    url(r'^$', views.home, name='home'),
    # packages
    url(r'^packages/$', views.packages, name='packages'),
    url(r'^package/(?P<package_id>\d+)/$', views.package, name='package'),
    url(r'^package/(?P<package_id>\d+)/graph/$', views.package_graph, name='package_graph'),
    url(r'^package/(?P<package_id>\d+)/delete/$', views.delete_package, name='delete_package'),
    url(r'^package/(?P<package_id>\d+)/update/header$', views.update_package_header, name='update_package_header'),
    url(r'^package/(?P<package_id>\d+)/edit/$', views.edit_create_package, name='edit_create_package'),
    url(r'^package/(?P<package_id>\d+)/add/(?P<item_id>\d+)/(?P<item_name>\w+)/$', views.add_item_to_package, name='add_item_to_package'),
    url(r'^package/(?P<package_id>\d+)/add/comment$', views.comment_package, name='comment_package'),
    # threat actors
    url(r'^threatactors/$', views.threatactors, name='threatactors'),
    url(r'^threatactor/(?P<threat_actor_id>\d+)/$', views.threatactor, name='threatactor'),
    url(r'^threatactor/(?P<threat_actor_id>\d+)/delete/$', views.delete_threatactor, name='delete_threatactor'),
    # campaigns
    url(r'^campaigns/$', views.campaigns, name='campaigns'),
    url(r'^campaign/(?P<campaign_id>\d+)/$', views.campaign, name='campaign'),
    url(r'^campaign/(?P<campaign_id>\d+)/delete/$', views.delete_campaign, name='delete_campaign'),
    # ttps
    url(r'^ttps/$', views.ttps, name='ttps'),
    url(r'^ttp/(?P<ttp_id>\d+)/$', views.ttp, name='ttp'),
    url(r'^ttp/(?P<ttp_id>\d+)/delete/$', views.delete_ttp, name='delete_ttp'),
    # indicators
    url(r'^indicators/$', views.indicators, name='indicators'),
    url(r'^indicator/(?P<indicator_id>\d+)/$', views.indicator, name='indicator'),
    url(r'^indicator/(?P<indicator_id>\d+)/delete/$', views.delete_indicator, name='delete_indicator'),
    # observables
    url(r'^observables/$', views.observables, name='observables'),
    url(r'^observable/(?P<observable_id>\d+)/$', views.observable, name='observable'),
    url(r'^observable/(?P<observable_id>\d+)/update/header$', views.update_observable_header, name='update_observable_header'),
    url(r'^observable/(?P<observable_id>\d+)/delete/$', views.delete_observable, name='delete_observable'),
    # stuff
    url(r'^mwinstance/(?P<mwi_id>\d+)/$', views.malware_instance, name='malware_instance'),
    url(r'^attpattern/(?P<ap_id>\d+)/$', views.attack_pattern, name='attack_pattern'),
]

