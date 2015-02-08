from rest_framework import serializers
from rest_framework.pagination import PaginationSerializer
from kraut_parser.models import Indicator, Indicator_Type, Observable, ThreatActor, Campaign, Confidence, Package

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

    class Meta:
        model = Observable
        fields = ('id', 'name', 'description', 'creation_time', 'last_modified', 'namespace', 'observable_type')

class PaginatedObservableSerializer(PaginationSerializer):
    class Meta:
        object_serializer_class = ObsSerializer
