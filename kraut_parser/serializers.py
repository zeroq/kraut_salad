from rest_framework import serializers
from rest_framework.pagination import PaginationSerializer
from kraut_parser.models import Indicator, Indicator_Type, Observable

class IndicatorSerializer(serializers.ModelSerializer):
    indicator_types = serializers.StringRelatedField(many=True)

    class Meta:
        model = Indicator
        fields = ('id', 'name', 'description', 'short_description', 'namespace', 'observable_composition_operator', 'indicator_types', 'confidence', 'related_indicators')

class PaginatedIndicatorSerializer(PaginationSerializer):
    class Meta:
        object_serializer_class = IndicatorSerializer


class ObservableSerializer(serializers.ModelSerializer):
    indicators = serializers.StringRelatedField(many=True)
    #file_object_set = serializers.StringRelatedField(many=True)

    class Meta:
        model = Observable
        fields = ('id', 'name', 'description', 'short_description', 'namespace', 'creation_time', 'last_modified', 'indicators', 'file_object_set', 'uri_object_set')

class PaginatedObservableSerializer(PaginationSerializer):
    class Meta:
        object_serializer_class = ObservableSerializer
