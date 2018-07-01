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
    url(r'^package/(?P<package_id>\d+)/del/comment/(?P<comment_id>\d+)/$', views.delete_comment_package, name='delete_comment_package'),
    # threat actors
    url(r'^threatactors/$', views.threatactors, name='threatactors'),
    url(r'^threatactor/(?P<threat_actor_id>\d+)/$', views.threatactor, name='threatactor'),
    url(r'^threatactor/(?P<threat_actor_id>\d+)/delete/$', views.delete_threatactor, name='delete_threatactor'),
    url(r'^threatactor/(?P<threat_actor_id>\d+)/edit/$', views.edit_create_threatactor, name='edit_create_threatactor'),
    url(r'^threatactor/(?P<threat_actor_id>\d+)/update/header$', views.update_ta_header, name='update_ta_header'),
    url(r'^threatactor/(?P<threat_actor_id>\d+)/add/comment$', views.comment_actor, name='comment_actor'),
    url(r'^threatactor/(?P<threat_actor_id>\d+)/del/comment/(?P<comment_id>\d+)/$', views.delete_comment_actor, name='delete_comment_actor'),
    # campaigns
    url(r'^campaigns/$', views.campaigns, name='campaigns'),
    url(r'^campaign/(?P<campaign_id>\d+)/$', views.campaign, name='campaign'),
    url(r'^campaign/(?P<campaign_id>\d+)/delete/$', views.delete_campaign, name='delete_campaign'),
    url(r'^campaign/(?P<campaign_id>\d+)/add/comment$', views.comment_campaign, name='comment_campaign'),
    url(r'^campaign/(?P<campaign_id>\d+)/update/header$', views.update_campaign_header, name='update_campaign_header'),
    url(r'^campaign/(?P<campaign_id>\d+)/del/comment/(?P<comment_id>\d+)/$', views.delete_comment_campaign, name='delete_comment_campaign'),
    # ttps
    url(r'^ttps/$', views.ttps, name='ttps'),
    url(r'^ttp/(?P<ttp_id>\d+)/$', views.ttp, name='ttp'),
    url(r'^ttp/(?P<ttp_id>\d+)/delete/$', views.delete_ttp, name='delete_ttp'),
    url(r'^ttp/(?P<ttp_id>\d+)/add/comment$', views.comment_ttp, name='comment_ttp'),
    url(r'^ttp/(?P<ttp_id>\d+)/update/header$', views.update_ttp_header, name='update_ttp_header'),
    url(r'^ttp/(?P<ttp_id>\d+)/del/comment/(?P<comment_id>\d+)/$', views.delete_comment_ttp, name='delete_comment_ttp'),
    # indicators
    url(r'^indicators/$', views.indicators, name='indicators'),
    url(r'^indicator/(?P<indicator_id>\d+)/$', views.indicator, name='indicator'),
    url(r'^indicator/(?P<indicator_id>\d+)/update/header$', views.update_indicator_header, name='update_indicator_header'),
    url(r'^indicator/(?P<indicator_id>\d+)/delete/$', views.delete_indicator, name='delete_indicator'),
    url(r'^indicator/(?P<indicator_id>\d+)/add/comment$', views.comment_indicator, name='comment_indicator'),
    url(r'^indicator/(?P<indicator_id>\d+)/del/comment/(?P<comment_id>\d+)/$', views.delete_comment_indicator, name='delete_comment_indicator'),
    # observables
    url(r'^observables/$', views.observables, name='observables'),
    url(r'^observable/(?P<observable_id>\d+)/$', views.observable, name='observable'),
    url(r'^observable/(?P<observable_id>\d+)/update/header$', views.update_observable_header, name='update_observable_header'),
    url(r'^observable/(?P<observable_id>\d+)/delete/$', views.delete_observable, name='delete_observable'),
    url(r'^observable/(?P<observable_id>\d+)/add/comment$', views.comment_observable, name='comment_observable'),
    url(r'^observable/(?P<observable_id>\d+)/del/comment/(?P<comment_id>\d+)/$', views.delete_comment_observable, name='delete_comment_observable'),
    # malware instance
    url(r'^mwinstances/$', views.malware_instances, name='malware_instances'),
    url(r'^mwinstance/(?P<mwi_id>\d+)/$', views.malware_instance, name='malware_instance'),
    url(r'^mwinstance/(?P<mwi_id>\d+)/delete/$', views.delete_malware_instance, name='delete_malware_instance'),
    url(r'^mwinstance/(?P<mwi_id>\d+)/update/header$', views.update_mwinstance_header, name='update_mwinstance_header'),
    # attack pattern
    url(r'^attpatterns/$', views.attack_patterns, name='attack_patterns'),
    url(r'^attpattern/(?P<ap_id>\d+)/$', views.attack_pattern, name='attack_pattern'),
    url(r'^mwinstance/(?P<ap_id>\d+)/delete/$', views.delete_attack_pattern, name='delete_attack_pattern'),
    url(r'^attpattern/(?P<ap_id>\d+)/update/header$', views.update_attpattern_header, name='update_attpattern_header'),
]

