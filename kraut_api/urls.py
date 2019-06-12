from django.conf.urls import url
from rest_framework.urlpatterns import format_suffix_patterns
from kraut_api import views

urlpatterns = [
    # indicators
    url(r'^indicators/$', views.indicator_list),
    url(r'^indicators/(?P<pk>[0-9]+)/$', views.indicator_detail),
    url(r'^indicators/(?P<pk>[0-9]+)/related/$', views.indicator_detail_related_indicators),
    url(r'^indicators/(?P<pk>[0-9]+)/ttps/$', views.indicator_detail_ttps),
    url(r'^indicators/(?P<pk>[0-9]+)/observables/$', views.indicator_detail_observables),
    url(r'^indicators/(?P<pk>[0-9]+)/compositions/$', views.indicator_detail_compositions),
    # observables
    url(r'^observables/$', views.observable_list),
    url(r'^observables/(?P<pk>[0-9]+)/$', views.observable_detail),
    url(r'^observables/(?P<pk>[0-9]+)/related_objects/$', views.observable_related_objects),
    url(r'^observables/(?P<pk>[0-9]+)/related_packages/$', views.observable_related_packages),
    url(r'^observables/(?P<pk>[0-9]+)/related_indicators/$', views.observable_related_indicators),
    # malware instances
    url(r'^malware_instances/$', views.malware_instances_list),
    # attack pattern
    url(r'^attack_patterns/$', views.attack_patterns_list),
    # campaign
    url(r'^campaigns/$', views.campaign_list),
    url(r'^campaigns/(?P<pk>[0-9]+)/$', views.campaign_detail),
    url(r'^campaigns/(?P<pk>[0-9]+)/related/$', views.campaign_detail_related_indicators),
    url(r'^campaigns/(?P<pk>[0-9]+)/associated/$', views.campaign_detail_associated_campaigns),
    url(r'^campaigns/(?P<pk>[0-9]+)/related_ttps/$', views.campaign_detail_related_ttps),
    url(r'^campaigns/(?P<pk>[0-9]+)/related_packages/$', views.campaign_detail_related_packages),
    # threat actor
    url(r'^threatactors/$', views.threatactor_list),
    url(r'^threatactors/(?P<pk>[0-9]+)/$', views.threatactor_detail),
    url(r'^threatactors/(?P<pk>[0-9]+)/associated/$', views.threatactor_detail_associated_threatactors),
    url(r'^threatactors/(?P<pk>[0-9]+)/campaigns/$', views.threatactor_detail_campaigns),
    url(r'^threatactors/(?P<pk>[0-9]+)/related_packages/$', views.threatactor_detail_related_packages),
    url(r'^threatactors/(?P<pk>[0-9]+)/observed_ttps/$', views.threatactor_detail_observed_ttps),
    # package
    url(r'^packages/$', views.package_list),
    url(r'^packages/(?P<pk>[0-9]+)/$', views.package_detail),
    url(r'^packages/(?P<pk>[0-9]+)/observables/$', views.package_detail_observables),
    url(r'^packages/(?P<pk>[0-9]+)/indicators/$', views.package_detail_indicators),
    url(r'^packages/(?P<pk>[0-9]+)/campaigns/$', views.package_detail_campaigns),
    url(r'^packages/(?P<pk>[0-9]+)/threatactors/$', views.package_detail_threatactors),
    url(r'^packages/(?P<pk>[0-9]+)/ttps/$', views.package_detail_ttps),
    url(r'^packages/(?P<pk>[0-9]+)/quick/(?P<otype>[a-zA-Z]+)/$', views.package_quick, name="package_quick"),
    url(r'^packagesd3/tree/(?P<pk>[0-9]+)/$', views.package_tree),
    # objects
    url(r'^objects/(?P<object_id>[0-9]+)/(?P<object_type>[a-zA-Z0-9]+)/packages/$', views.object_get_packages),
    url(r'^objects/(?P<object_id>[0-9]+)/(?P<object_type>[a-zA-Z0-9]+)/observables/$', views.object_get_observables),
    url(r'^objects/hashes/$', views.object_hash_list),
    url(r'^objects/ips/$', views.object_ip_list),
    url(r'^objects/domains/$', views.object_domain_list),
    url(r'^compositions/(?P<pk>[0-9]+)/$', views.composition_details),
    url(r'^compositions/(?P<pk>[0-9]+)/d3/$', views.composition_details_d3),
    # incident
    url(r'^incident/contacts/$', views.contact_list),
    url(r'^incident/handlers/$', views.handler_list),
    url(r'^incident/tasks/$', views.template_tasks),
    url(r'^incident/(?P<incident_id>[0-9]+)/handlers/$', views.handler_list_incident),
    url(r'^incident/(?P<incident_id>[0-9]+)/contacts/$', views.contact_list_incident),
    url(r'^incidents/$', views.incident_list),
    # ttp
    url(r'^ttps/$', views.ttp_list),
    url(r'^ttp/(?P<pk>[0-9]+)/related_ttps/$', views.ttp_related_ttps),
    url(r'^ttp/(?P<pk>[0-9]+)/related_packages/$', views.ttp_related_packages),
    url(r'^ttp/(?P<pk>[0-9]+)/malware_instances/$', views.ttp_malware_instances),
    url(r'^ttp/(?P<pk>[0-9]+)/attack_patterns/$', views.ttp_attack_patterns),
    # taxii
    url(r'^taxii/feed/information/$', views.taxii_feed_information),
    url(r'^taxii/servers/$', views.taxii_server_list),
    url(r'^taxii/collections/$', views.taxii_collection_list),
    url(r'^comments/(?P<object_type>[a-zA-Z0-9]+)/$', views.list_comments),
]

urlpatterns = format_suffix_patterns(urlpatterns)
