# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from rest_framework import serializers
from rest_framework.pagination import PaginationSerializer
from kraut_parser.models import Indicator, Indicator_Type, Observable, ThreatActor, Campaign, Confidence, Package, ObservableComposition
from kraut_intel.utils import get_icon_for_namespace
from kraut_incident.models import Contact

import datetime

################### PACKAGE #####################

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
        return get_icon_for_namespace(obj.namespace)

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

################### THREAT ACTOR #####################

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
        fields = ('id', 'name', 'description', 'creation_time', 'last_modified', 'namespace', 'namespace_icon', 'short_description')

    def get_namespace_icon(self, obj):
        return get_icon_for_namespace(obj.namespace)

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

################### CAMPAIGN #####################

# Campaign Details
class CampaignSerializer(serializers.ModelSerializer):
    confidence = serializers.StringRelatedField(many=True)

    class Meta:
        model = Campaign
        fields = ('id', 'name', 'description', 'short_description', 'namespace', 'creation_time', 'last_modified', 'status', 'confidence', 'related_indicators', 'associated_campaigns')

# Campaign List
class CampSerializer(serializers.ModelSerializer):
    creation_time = serializers.SerializerMethodField()
    last_modified = serializers.SerializerMethodField()
    namespace_icon = serializers.SerializerMethodField()
    confidence = serializers.SerializerMethodField()

    class Meta:
        model = Campaign
        fields = ('id', 'name', 'description', 'creation_time', 'last_modified', 'namespace', 'namespace_icon', 'confidence', 'status')

    def get_namespace_icon(self, obj):
        return get_icon_for_namespace(obj.namespace)

    def get_creation_time(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_last_modified(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_confidence(self, obj):
        try:
            return obj.confidence.first().value
        except:
            return "Unknown"

# Paginated Campaigns
class PaginatedCampaignSerializer(PaginationSerializer):
    iTotalRecords = serializers.ReadOnlyField(source='paginator.count')
    iTotalDisplayRecords = serializers.ReadOnlyField(source='paginator.count')

    class Meta:
        object_serializer_class = CampSerializer


################### INDICATOR #####################

# Indicator Details
class IndicatorSerializer(serializers.ModelSerializer):
    indicator_types = serializers.StringRelatedField(many=True)

    class Meta:
        model = Indicator
        fields = ('id', 'name', 'description', 'short_description', 'namespace', 'indicator_types', 'confidence', 'related_indicators', 'creation_time', 'last_modified', 'indicator_composition_operator')

# Indicator List
class IndSerializer(serializers.ModelSerializer):
    creation_time = serializers.SerializerMethodField()
    last_modified = serializers.SerializerMethodField()
    namespace_icon = serializers.SerializerMethodField()

    class Meta:
        model = Indicator
        fields = ('id', 'name', 'description', 'creation_time', 'last_modified', 'namespace', 'namespace_icon')

    def get_namespace_icon(self, obj):
        return get_icon_for_namespace(obj.namespace)

    def get_creation_time(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_last_modified(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

# Paginated Indicators
class PaginatedIndicatorSerializer(PaginationSerializer):
    iTotalRecords = serializers.ReadOnlyField(source='paginator.count')
    iTotalDisplayRecords = serializers.ReadOnlyField(source='paginator.count')

    class Meta:
        object_serializer_class = IndSerializer

# Indicator List
class Ind2Serializer(serializers.ModelSerializer):
    indicator_types = serializers.SerializerMethodField()
    confidence = serializers.SerializerMethodField()

    class Meta:
        model = Indicator
        fields = ('id', 'name', 'description', 'indicator_types', 'confidence')

    def get_indicator_types(self, obj):
        try:
            return obj.indicator_types.last().itype
        except:
            return None

    def get_confidence(self, obj):
        return obj.confidence.first().value

# Paginated Indicators
class PaginatedIndicator2Serializer(PaginationSerializer):
    iTotalRecords = serializers.ReadOnlyField(source='paginator.count')
    iTotalDisplayRecords = serializers.ReadOnlyField(source='paginator.count')

    class Meta:
        object_serializer_class = Ind2Serializer

################### OBSERVABLE COMPOSITION #####################

class ObservableCompositionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ObservableComposition
        fields = ('id', 'name', 'operator')

class PaginatedCompositionSerializer(PaginationSerializer):
    iTotalRecords = serializers.ReadOnlyField(source='paginator.count')
    iTotalDisplayRecords = serializers.ReadOnlyField(source='paginator.count')

    class Meta:
        object_serializer_class = ObservableCompositionSerializer

################### OBSERVABLE #####################

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
        return get_icon_for_namespace(obj.namespace)

    def get_short_name(self, obj):
        if len(obj.name)>35:
            return "%s ..." % (obj.name[:35])
        return obj.name

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


################### INCIDENT CONTACTS #####################

# Contact List
class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = ('id', 'firstname', 'lastname')

# Paginated Contacts
class PaginatedContactSerializer(PaginationSerializer):
    iTotalRecords = serializers.ReadOnlyField(source='paginator.count')
    iTotalDisplayRecords = serializers.ReadOnlyField(source='paginator.count')

    class Meta:
        object_serializer_class = ContactSerializer
