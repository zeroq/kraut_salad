# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.templatetags.static import static

from rest_framework import serializers
from rest_framework.pagination import PaginationSerializer
from kraut_parser.models import Indicator, Indicator_Type, Observable, ThreatActor, Campaign, Confidence, Package

import datetime

# Package
class PackageSerializer(serializers.ModelSerializer):

    class Meta:
        model = Package
        fields = ('id', 'name', 'description', 'short_description', 'namespace', 'creation_time', 'last_modified', 'version', 'package_id', 'source', 'produced_time', 'threat_actors', 'campaigns', 'indicators', 'observables')

class PackSerializer(serializers.ModelSerializer):

    class Meta:
        model = Package
        fields = ('id', 'name', 'description', 'creation_time', 'last_modified', 'namespace')

class PaginatedPackageSerializer(PaginationSerializer):
    class Meta:
        object_serializer_class = PackSerializer

# Threat Actor
class ThreatActorSerializer(serializers.ModelSerializer):
    campaigns = serializers.StringRelatedField(many=True)

    class Meta:
        model = ThreatActor
        fields = ('id', 'name', 'description', 'short_description', 'namespace', 'creation_time', 'last_modified', 'campaigns', 'associated_threat_actors')

class TASerializer(serializers.ModelSerializer):

    class Meta:
        model = ThreatActor
        fields = ('id', 'name', 'description', 'creation_time', 'last_modified', 'namespace')

class PaginatedThreatActorSerializer(PaginationSerializer):
    class Meta:
        object_serializer_class = TASerializer

# Campaign
class CampaignSerializer(serializers.ModelSerializer):
    confidence = serializers.StringRelatedField(many=True)

    class Meta:
        model = Campaign
        fields = ('id', 'name', 'description', 'short_description', 'namespace', 'creation_time', 'last_modified', 'status', 'confidence', 'related_indicators', 'associated_campaigns')

class CampSerializer(serializers.ModelSerializer):

    class Meta:
        model = Campaign
        fields = ('id', 'name', 'description', 'creation_time', 'last_modified', 'namespace')

class PaginatedCampaignSerializer(PaginationSerializer):
    class Meta:
        object_serializer_class = CampSerializer

# Indicator
class IndicatorSerializer(serializers.ModelSerializer):
    indicator_types = serializers.StringRelatedField(many=True)

    class Meta:
        model = Indicator
        fields = ('id', 'name', 'description', 'short_description', 'namespace', 'observable_composition_operator', 'indicator_types', 'confidence', 'related_indicators', 'creation_time', 'last_modified', 'indicator_composition_operator')

class IndSerializer(serializers.ModelSerializer):

    class Meta:
        model = Indicator
        fields = ('id', 'name', 'description', 'creation_time', 'last_modified', 'namespace')

class PaginatedIndicatorSerializer(PaginationSerializer):
    class Meta:
        object_serializer_class = IndSerializer

# Observable
class ObservableSerializer(serializers.ModelSerializer):
    indicators = serializers.StringRelatedField(many=True)

    class Meta:
        model = Observable
        fields = ('id', 'name', 'description', 'short_description', 'namespace', 'creation_time', 'last_modified', 'indicators', 'observable_type')

class ObsSerializer(serializers.ModelSerializer):
    creation_time = serializers.SerializerMethodField()
    last_modified = serializers.SerializerMethodField()
    short_name = serializers.SerializerMethodField()
    namespace_icon = serializers.SerializerMethodField()

    class Meta:
        model = Observable
        fields = ('id', 'name', 'description', 'creation_time', 'last_modified', 'namespace', 'observable_type', 'short_name', 'namespace_icon')

    def get_namespace_icon(self, obj):
        ### TODO: create table for namespace <-> icon relation and get it here
        return static('ns_icon/octalpus.png')

    def get_short_name(self, obj):
        return "%s ..." % (obj.name[:35])

    def get_creation_time(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_last_modified(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

class PaginatedObservableSerializer(PaginationSerializer):
    iTotalRecords = serializers.ReadOnlyField(source='paginator.count')
    iTotalDisplayRecords = serializers.ReadOnlyField(source='paginator.count')

    class Meta:
        object_serializer_class = ObsSerializer
