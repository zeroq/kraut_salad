# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.templatetags.static import static

from rest_framework import serializers
from rest_framework.pagination import PaginationSerializer
from kraut_parser.models import Indicator, Indicator_Type, Observable, ThreatActor, Campaign, Confidence, Package, HTTPSession_Object
from kraut_intel.models import NamespaceIcon

import datetime

# Package D3 Json
class PackageD3Serializer(serializers.ModelSerializer):
    children = serializers.SerializerMethodField()
    size = serializers.SerializerMethodField()

    class Meta:
        model = Package
        fields = ('name', 'children', 'size')

    def get_size(self, obj):
        return 1000

    def get_children(self, obj):
        children = []
        """ check for threat actors """
        child_dict = {
                'name': 'threat_actors',
                'children': []
        }
        for t in obj.threat_actors.all():
            t_dict = {'name': t.name, 'size': 5}
            child_dict['children'].append(t_dict)
        if len(child_dict['children'])>0:
            children.append(child_dict)
        """ check for campaigns """
        child_dict = {
                'name': 'campaigns',
                'children': []
        }
        for c in obj.campaigns.all():
            c_dict = {'name': c.name, 'size': 5}
            child_dict['children'].append(c_dict)
        if len(child_dict['children'])>0:
            children.append(child_dict)
        """ check for indicators """
        child_dict = {
                'name': 'indicators',
                'children': []
        }
        for ind in obj.indicators.all():
            ind_child_dict = {'name': ind.name[:15], 'children': []}
            observable_childs = {}
            for obs in obj.observables.filter(indicators=ind):
                obs_child = {'name': obs.name, 'size': 5}
                if obs.observable_type in observable_childs:
                    observable_childs[obs.observable_type].append(obs_child)
                else:
                    observable_childs[obs.observable_type] = [obs_child]
            for key in observable_childs:
                ind_child_dict['children'].append({'name': key, 'children': observable_childs[key]})
            child_dict['children'].append(ind_child_dict)
        if len(child_dict['children'])>0:
            children.append(child_dict)
        """ check for observables """
        child_dict = {
            'name': 'observables',
            'children': []
        }
        observable_childs = {}
        for obs in obj.observables.all():
            if obs.observable_type == 'HTTPSessionObjectType':
                for https in HTTPSession_Object.objects.filter(observables=obs):
                    obs_child_dict = {'name': https.client_request.domain_name.uri_value+https.client_request.request_uri, 'size': 5}
            else:
                obs_child_dict = {'name': obs.name, 'size': 5}
            if obs.observable_type in observable_childs:
                observable_childs[obs.observable_type].append(obs_child_dict)
            else:
                observable_childs[obs.observable_type] = [obs_child_dict]
        for key in observable_childs:
            child_dict['children'].append({'name': key, 'children': observable_childs[key]})
        if len(child_dict['children'])>0:
            children.append(child_dict)
        return children

# Package Details
class PackageSerializer(serializers.ModelSerializer):

    class Meta:
        model = Package
        fields = ('id', 'name', 'description', 'short_description', 'namespace', 'creation_time', 'last_modified', 'version', 'package_id', 'source', 'produced_time', 'threat_actors', 'campaigns', 'indicators', 'observables')

# Packages List
class PackSerializer(serializers.ModelSerializer):
    creation_time = serializers.SerializerMethodField()
    last_modified = serializers.SerializerMethodField()
    namespace_icon = serializers.SerializerMethodField()

    class Meta:
        model = Package
        fields = ('id', 'name', 'description', 'creation_time', 'last_modified', 'namespace', 'namespace_icon')

    def get_namespace_icon(self, obj):
        try:
            icon = NamespaceIcon.objects.get(namespace=obj.namespace)
        except:
            return static('ns_icon/octalpus.png')
        return static('ns_icon/%s' % (icon.icon))

    def get_creation_time(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_last_modified(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

# Paginated Packages
class PaginatedPackageSerializer(PaginationSerializer):
    iTotalRecords = serializers.ReadOnlyField(source='paginator.count')
    iTotalDisplayRecords = serializers.ReadOnlyField(source='paginator.count')

    class Meta:
        object_serializer_class = PackSerializer

# Threat Actor Details
class ThreatActorSerializer(serializers.ModelSerializer):
    campaigns = serializers.StringRelatedField(many=True)

    class Meta:
        model = ThreatActor
        fields = ('id', 'name', 'description', 'short_description', 'namespace', 'creation_time', 'last_modified', 'campaigns', 'associated_threat_actors')

# Threat Actor List
class TASerializer(serializers.ModelSerializer):
    creation_time = serializers.SerializerMethodField()
    last_modified = serializers.SerializerMethodField()
    namespace_icon = serializers.SerializerMethodField()

    class Meta:
        model = ThreatActor
        fields = ('id', 'name', 'description', 'creation_time', 'last_modified', 'namespace', 'namespace_icon')

    def get_namespace_icon(self, obj):
        try:
            icon = NamespaceIcon.objects.get(namespace=obj.namespace)
        except:
            return static('ns_icon/octalpus.png')
        return static('ns_icon/%s' % (icon.icon))

    def get_creation_time(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_last_modified(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")


# Threat Actor Paginated
class PaginatedThreatActorSerializer(PaginationSerializer):
    iTotalRecords = serializers.ReadOnlyField(source='paginator.count')
    iTotalDisplayRecords = serializers.ReadOnlyField(source='paginator.count')

    class Meta:
        object_serializer_class = TASerializer

# Campaign Details
class CampaignSerializer(serializers.ModelSerializer):
    confidence = serializers.StringRelatedField(many=True)

    class Meta:
        model = Campaign
        fields = ('id', 'name', 'description', 'short_description', 'namespace', 'creation_time', 'last_modified', 'status', 'confidence', 'related_indicators', 'associated_campaigns')

# Campaign List
class CampSerializer(serializers.ModelSerializer):

    class Meta:
        model = Campaign
        fields = ('id', 'name', 'description', 'creation_time', 'last_modified', 'namespace')

# Paginated Campaigns
class PaginatedCampaignSerializer(PaginationSerializer):
    iTotalRecords = serializers.ReadOnlyField(source='paginator.count')
    iTotalDisplayRecords = serializers.ReadOnlyField(source='paginator.count')

    class Meta:
        object_serializer_class = CampSerializer

# Indicator Details
class IndicatorSerializer(serializers.ModelSerializer):
    indicator_types = serializers.StringRelatedField(many=True)

    class Meta:
        model = Indicator
        fields = ('id', 'name', 'description', 'short_description', 'namespace', 'observable_composition_operator', 'indicator_types', 'confidence', 'related_indicators', 'creation_time', 'last_modified', 'indicator_composition_operator')

# Indicator List
class IndSerializer(serializers.ModelSerializer):

    class Meta:
        model = Indicator
        fields = ('id', 'name', 'description', 'creation_time', 'last_modified', 'namespace')

# Paginated Indicators
class PaginatedIndicatorSerializer(PaginationSerializer):
    iTotalRecords = serializers.ReadOnlyField(source='paginator.count')
    iTotalDisplayRecords = serializers.ReadOnlyField(source='paginator.count')

    class Meta:
        object_serializer_class = IndSerializer

# Observable Details
class ObservableSerializer(serializers.ModelSerializer):
    indicators = serializers.StringRelatedField(many=True)

    class Meta:
        model = Observable
        fields = ('id', 'name', 'description', 'short_description', 'namespace', 'creation_time', 'last_modified', 'indicators', 'observable_type')

# Observables List
class ObsSerializer(serializers.ModelSerializer):
    creation_time = serializers.SerializerMethodField()
    last_modified = serializers.SerializerMethodField()
    short_name = serializers.SerializerMethodField()
    namespace_icon = serializers.SerializerMethodField()

    class Meta:
        model = Observable
        fields = ('id', 'name', 'description', 'creation_time', 'last_modified', 'namespace', 'observable_type', 'short_name', 'namespace_icon')

    def get_namespace_icon(self, obj):
        try:
            icon = NamespaceIcon.objects.get(namespace=obj.namespace)
        except:
            return static('ns_icon/octalpus.png')
        return static('ns_icon/%s' % (icon.icon))

    def get_short_name(self, obj):
        return "%s ..." % (obj.name[:35])

    def get_creation_time(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_last_modified(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

# Paginated Observables
class PaginatedObservableSerializer(PaginationSerializer):
    iTotalRecords = serializers.ReadOnlyField(source='paginator.count')
    iTotalDisplayRecords = serializers.ReadOnlyField(source='paginator.count')

    class Meta:
        object_serializer_class = ObsSerializer
