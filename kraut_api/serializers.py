# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from rest_framework import serializers
from rest_framework.pagination import PaginationSerializer
from kraut_parser.models import Indicator, Indicator_Type, Observable, ThreatActor, Campaign, Confidence, Package, ObservableComposition, File_Object, TTP, Address_Object, URI_Object
from kraut_parser.models import MalwareInstance, AttackPattern
from kraut_intel.utils import get_icon_for_namespace
from kraut_incident.models import Contact, Handler, Incident

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
    namespace = serializers.SerializerMethodField()
    short_name = serializers.SerializerMethodField()

    class Meta:
        model = Package
        fields = ('id', 'name', 'description', 'creation_time', 'last_modified', 'namespace', 'namespace_icon', 'short_name')

    def get_namespace_icon(self, obj):
        return get_icon_for_namespace(obj.namespace.last().namespace)

    def get_namespace(self, obj):
        return obj.namespace.last().namespace

    def get_creation_time(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_last_modified(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_short_name(self, obj):
        if len(obj.name)>55:
            return "%s ..." % (obj.name[:55])
        return obj.name

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

################### TTPS #####################

# TTP List
class TTPSerializer(serializers.ModelSerializer):
    creation_time = serializers.SerializerMethodField()
    last_modified = serializers.SerializerMethodField()
    namespace_icon = serializers.SerializerMethodField()

    class Meta:
        model = TTP
        fields = ('id', 'name', 'description', 'short_description', 'namespace', 'namespace_icon', 'creation_time', 'last_modified', 'related_ttps')

    def get_namespace_icon(self, obj):
        return get_icon_for_namespace(obj.namespace)

    def get_creation_time(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_last_modified(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

# Paginated TTPs
class PaginatedTTPSerializer(PaginationSerializer):
    iTotalRecords = serializers.ReadOnlyField(source='paginator.count')
    iTotalDisplayRecords = serializers.ReadOnlyField(source='paginator.count')

    class Meta:
        object_serializer_class = TTPSerializer


################### MALWARE INSTANCE #####################

class MalwareInstance(serializers.ModelSerializer):
    creation_time = serializers.SerializerMethodField()
    last_modified = serializers.SerializerMethodField()
    subname = serializers.SerializerMethodField()

    class Meta:
        model = MalwareInstance
        fields = ('id', 'name', 'description', 'short_description', 'creation_time', 'last_modified', 'subname')

    def get_creation_time(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_last_modified(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_subname(self, obj):
        try:
            return obj.malwareinstancenames_set.first().name
        except:
            return "Unknown"

# Paginated Malware Instances
class PaginatedMalwareInstanceSerializer(PaginationSerializer):
    iTotalRecords = serializers.ReadOnlyField(source='paginator.count')
    iTotalDisplayRecords = serializers.ReadOnlyField(source='paginator.count')

    class Meta:
        object_serializer_class = MalwareInstance



################### ATTACK PATTERN #####################

class AttackPattern(serializers.ModelSerializer):
    creation_time = serializers.SerializerMethodField()
    last_modified = serializers.SerializerMethodField()

    class Meta:
        model = AttackPattern

    def get_creation_time(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_last_modified(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")


class PaginatedAttackPatternSerializer(PaginationSerializer):
    iTotalRecords = serializers.ReadOnlyField(source='paginator.count')
    iTotalDisplayRecords = serializers.ReadOnlyField(source='paginator.count')

    class Meta:
        object_serializer_class = AttackPattern


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

################### INCIDENT HANDLER #####################

# Handler List
class HandlerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Handler
        fields = ('id', 'firstname', 'lastname')

# Paginated Contacts
class PaginatedHandlerSerializer(PaginationSerializer):
    iTotalRecords = serializers.ReadOnlyField(source='paginator.count')
    iTotalDisplayRecords = serializers.ReadOnlyField(source='paginator.count')

    class Meta:
        object_serializer_class = HandlerSerializer

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

################### INCIDENT #####################

class IncidentSerializer(serializers.ModelSerializer):
    status = serializers.StringRelatedField()
    category = serializers.StringRelatedField()

    class Meta:
        model = Incident
        fields = ('id', 'incident_number', 'title', 'creation_time', 'last_modified', 'status', 'category')

class PaginatedIncidentSerializer(PaginationSerializer):
    iTotalRecords = serializers.ReadOnlyField(source='paginator.count')
    iTotalDisplayRecords = serializers.ReadOnlyField(source='paginator.count')

    class Meta:
        object_serializer_class = IncidentSerializer


################### OBJECT #####################

class FileObjectSerializer(serializers.ModelSerializer):
    observables = ObservableSerializer(many=True)

    class Meta:
        model = File_Object
        fields = ('id', 'md5_hash', 'sha256_hash', 'observables')

class PaginatedFileObjectSerializer(PaginationSerializer):
    iTotalRecords = serializers.ReadOnlyField(source='paginator.count')
    iTotalDisplayRecords = serializers.ReadOnlyField(source='paginator.count')

    class Meta:
        object_serializer_class = FileObjectSerializer

class AddressObjectSerializer(serializers.ModelSerializer):
    observables = ObservableSerializer(many=True)

    class Meta:
        model = Address_Object
        fields = ('id', 'address_value', 'category', 'observables')

class PaginatedAddressObjectSerializer(PaginationSerializer):
    iTotalRecords = serializers.ReadOnlyField(source='paginator.count')
    iTotalDisplayRecords = serializers.ReadOnlyField(source='paginator.count')

    class Meta:
        object_serializer_class = AddressObjectSerializer

class URIObjectSerializer(serializers.ModelSerializer):
    observables = ObservableSerializer(many=True)

    class Meta:
        model = URI_Object
        fields = ('id', 'uri_value', 'uri_type', 'observables')

class PaginatedURIObjectSerializer(PaginationSerializer):
    iTotalRecords = serializers.ReadOnlyField(source='paginator.count')
    iTotalDisplayRecords = serializers.ReadOnlyField(source='paginator.count')

    class Meta:
        object_serializer_class = URIObjectSerializer
