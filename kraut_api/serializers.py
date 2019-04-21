# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from rest_framework import serializers
from kraut_parser.models import Indicator, Indicator_Type, Observable, ThreatActor, Campaign, Confidence, Package, ObservableComposition, File_Object, TTP, Address_Object, URI_Object
from kraut_parser.models import MalwareInstance, AttackPattern
from kraut_intel.utils import get_icon_for_namespace
from kraut_intel.models import PackageComment, NamespaceIcon, ThreatActorComment, CampaignComment, TTPComment, IndicatorComment, ObservableComment
from kraut_incident.models import Contact, Handler, Incident
from kraut_sharing.models import TAXII_Remote_Server, TAXII_Remote_Collection

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
        return obj.last_modified.strftime("%Y-%m-%d %H:%M:%S")

    def get_short_name(self, obj):
        if len(obj.name)>55:
            return "%s ..." % (obj.name[:55])
        return obj.name

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
    namespace = serializers.SerializerMethodField()
    namespace_icon = serializers.SerializerMethodField()

    class Meta:
        model = ThreatActor
        fields = ('id', 'name', 'description', 'creation_time', 'last_modified', 'namespace', 'namespace_icon', 'short_description')

    def get_namespace_icon(self, obj):
        return get_icon_for_namespace(obj.namespace.last().namespace)

    def get_namespace(self, obj):
        return obj.namespace.last().namespace

    def get_creation_time(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_last_modified(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

################### TTPS #####################

# TTP List
class TTPSerializer(serializers.ModelSerializer):
    creation_time = serializers.SerializerMethodField()
    last_modified = serializers.SerializerMethodField()
    namespace = serializers.SerializerMethodField()
    namespace_icon = serializers.SerializerMethodField()

    class Meta:
        model = TTP
        fields = ('id', 'name', 'description', 'short_description', 'namespace', 'namespace_icon', 'creation_time', 'last_modified', 'related_ttps')

    def get_namespace_icon(self, obj):
        return get_icon_for_namespace(obj.namespace.last().namespace)

    def get_namespace(self, obj):
        return obj.namespace.last().namespace

    def get_creation_time(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_last_modified(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

################### MALWARE INSTANCE #####################

class MalwareInstanceSerializer(serializers.ModelSerializer):
    short_name = serializers.SerializerMethodField()
    creation_time = serializers.SerializerMethodField()
    last_modified = serializers.SerializerMethodField()
    subname = serializers.SerializerMethodField()
    mwitype = serializers.SerializerMethodField()

    class Meta:
        model = MalwareInstance
        fields = ('id', 'name', 'short_name', 'description', 'short_description', 'creation_time', 'last_modified', 'subname', 'mwitype')

    def get_short_name(self, obj):
        if len(obj.name)>55:
            return "%s ..." % (obj.name[:55])
        return obj.name

    def get_creation_time(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_last_modified(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_subname(self, obj):
        try:
            return obj.malwareinstancenames_set.first().name
        except:
            return "Unknown"

    def get_mwitype(self, obj):
        try:
            return obj.malwareinstancetypes_set.first()._type
        except:
            return "Unknown"

################### ATTACK PATTERN #####################

class AttackPatternSerializer(serializers.ModelSerializer):
    short_name = serializers.SerializerMethodField()
    creation_time = serializers.SerializerMethodField()
    last_modified = serializers.SerializerMethodField()

    class Meta:
        model = AttackPattern
        fields = ('id', 'name', 'short_name', 'description', 'short_description', 'creation_time', 'last_modified', 'capec_id')

    def get_short_name(self, obj):
        if len(obj.name)>55:
            return "%s ..." % (obj.name[:55])
        return obj.name

    def get_creation_time(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_last_modified(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

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
    namespace = serializers.SerializerMethodField()
    namespace_icon = serializers.SerializerMethodField()
    confidence = serializers.SerializerMethodField()

    class Meta:
        model = Campaign
        fields = ('id', 'name', 'description', 'creation_time', 'last_modified', 'namespace', 'namespace_icon', 'confidence', 'status')

    def get_namespace_icon(self, obj):
        return get_icon_for_namespace(obj.namespace.last().namespace)

    def get_namespace(self, obj):
        return obj.namespace.last().namespace

    def get_creation_time(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_last_modified(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_confidence(self, obj):
        try:
            return obj.confidence.first().value
        except:
            return "Unknown"

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
    namespace = serializers.SerializerMethodField()
    namespace_icon = serializers.SerializerMethodField()

    class Meta:
        model = Indicator
        fields = ('id', 'name', 'description', 'creation_time', 'last_modified', 'namespace', 'namespace_icon')

    def get_namespace_icon(self, obj):
        return get_icon_for_namespace(obj.namespace.last().namespace)

    def get_namespace(self, obj):
        return obj.namespace.last().namespace

    def get_creation_time(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_last_modified(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

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

################### OBSERVABLE COMPOSITION #####################

class ObservableCompositionSerializer(serializers.ModelSerializer):
    class Meta:
        model = ObservableComposition
        fields = ('id', 'name', 'operator')

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
    namespace = serializers.SerializerMethodField()
    namespace_icon = serializers.SerializerMethodField()

    class Meta:
        model = Observable
        fields = ('id', 'name', 'description', 'creation_time', 'last_modified', 'namespace', 'observable_type', 'short_name', 'namespace_icon')

    def get_namespace_icon(self, obj):
        return get_icon_for_namespace(obj.namespace.last().namespace)

    def get_namespace(self, obj):
        return obj.namespace.last().namespace

    def get_short_name(self, obj):
        if len(obj.name)>35:
            return "%s ..." % (obj.name[:35])
        return obj.name

    def get_creation_time(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

    def get_last_modified(self, obj):
        return obj.creation_time.strftime("%Y-%m-%d %H:%M:%S")

################### INCIDENT HANDLER #####################

# Handler List
class HandlerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Handler
        fields = ('id', 'firstname', 'lastname')

################### INCIDENT CONTACTS #####################

# Contact List
class ContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = ('id', 'firstname', 'lastname')

################### INCIDENT #####################

class IncidentSerializer(serializers.ModelSerializer):
    status = serializers.StringRelatedField()
    category = serializers.StringRelatedField()
    severity = serializers.StringRelatedField()

    class Meta:
        model = Incident
        fields = ('id', 'incident_number', 'title', 'creation_time', 'last_modified', 'status', 'category', 'severity')

################### SHARING #####################

class ServersSerializer(serializers.ModelSerializer):

    class Meta:
        model = TAXII_Remote_Server
        fields = ('id', 'name', 'host', 'path')

class CollectionSerializer(serializers.ModelSerializer):
    last_modified = serializers.SerializerMethodField()

    class Meta:
        model = TAXII_Remote_Collection
        fields = ('id', 'name', 'creation_time', 'last_modified', 'subscribed', 'collection_type', 'poll_period', 'begin_timestamp')

    def get_last_modified(self, obj):
        #delta = datetime.datetime.now() - obj.last_modified.replace(tzinfo=None)
        #return "%s days ago ..." % (delta.days)
        return obj.last_modified.strftime("%Y-%m-%d")

################### OBJECT #####################

class FileObjectSerializer(serializers.ModelSerializer):
    observables = ObservableSerializer(many=True)

    class Meta:
        model = File_Object
        fields = ('id', 'md5_hash', 'sha256_hash', 'observables')

class AddressObjectSerializer(serializers.ModelSerializer):
    observables = ObservableSerializer(many=True)

    class Meta:
        model = Address_Object
        fields = ('id', 'address_value', 'category', 'observables')

class URIObjectSerializer(serializers.ModelSerializer):
    observables = ObservableSerializer(many=True)
    short_value = serializers.SerializerMethodField()

    class Meta:
        model = URI_Object
        fields = ('id', 'uri_value', 'uri_type', 'observables', 'short_value')

    def get_short_value(self, obj):
        if len(obj.uri_value)>70:
            return "%s ..." % (obj.uri_value[:70])
        return obj.uri_value

################### COMMENTS #####################

class PackageCommentSerializer(serializers.ModelSerializer):
    author = serializers.SerializerMethodField()

    class Meta:
        model = PackageComment
        fields = ('id', 'author', 'creation_time', 'package_reference', 'ctext')

    def get_author(self, obj):
        return obj.author.username

########################
# Threat Actor Comment #
########################

class ActorCommentSerializer(serializers.ModelSerializer):
    author = serializers.SerializerMethodField()

    class Meta:
        model = ThreatActorComment
        fields = ('id', 'author', 'creation_time', 'actor_reference', 'ctext')

    def get_author(self, obj):
        return obj.author.username

####################
# Campaign Comment #
####################

class CampaignCommentSerializer(serializers.ModelSerializer):
    author = serializers.SerializerMethodField()

    class Meta:
        model = CampaignComment
        fields = ('id', 'author', 'creation_time', 'campaign_reference', 'ctext')

    def get_author(self, obj):
        return obj.author.username

###############
# TTP Comment #
###############

class TTPCommentSerializer(serializers.ModelSerializer):
    author = serializers.SerializerMethodField()

    class Meta:
        model = TTPComment
        fields = ('id', 'author', 'creation_time', 'ttp_reference', 'ctext')

    def get_author(self, obj):
        return obj.author.username

#####################
# Indicator Comment #
#####################

class IndicatorCommentSerializer(serializers.ModelSerializer):
    author = serializers.SerializerMethodField()

    class Meta:
        model = IndicatorComment
        fields = ('id', 'author', 'creation_time', 'indicator_reference', 'ctext')

    def get_author(self, obj):
        return obj.author.username

######################
# Observable Comment #
######################

class ObservableCommentSerializer(serializers.ModelSerializer):
    author = serializers.SerializerMethodField()

    class Meta:
        model = ObservableComment
        fields = ('id', 'author', 'creation_time', 'observable_reference', 'ctext')

    def get_author(self, obj):
        return obj.author.username

