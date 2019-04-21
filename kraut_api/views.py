# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.http import JsonResponse, HttpResponse
from django.urls import reverse
from django.db.models import Q
from django.core.paginator import Paginator
from rest_framework import status
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.authentication import SessionAuthentication
from kraut_parser.models import Indicator, Observable, Campaign, ThreatActor, Package, ObservableComposition, File_Object, TTP, RelatedTTP, MalwareInstance, AttackPattern
from kraut_parser.models import Address_Object, URI_Object
from kraut_api.paginators import CustomPaginator
# Indicator
from kraut_api.serializers import IndicatorSerializer, IndSerializer, Ind2Serializer, IndicatorCommentSerializer
# Observable
from kraut_api.serializers import ObservableSerializer, ObsSerializer, ObservableCommentSerializer, ObservableCompositionSerializer
# Campaign
from kraut_api.serializers import CampaignSerializer, CampSerializer, CampaignCommentSerializer
# Threat Actor
from kraut_api.serializers import ThreatActorSerializer, TASerializer, ActorCommentSerializer
# Package
from kraut_api.serializers import PackageSerializer, PackSerializer, PackageCommentSerializer
# Incident
from kraut_api.serializers import IncidentSerializer, ContactSerializer, HandlerSerializer
# Objects
from kraut_api.serializers import AddressObjectSerializer, URIObjectSerializer, FileObjectSerializer
# TTPs
from kraut_api.serializers import TTPSerializer, TTPCommentSerializer
# Malware Instance and Attack Pattern
from kraut_api.serializers import MalwareInstanceSerializer, AttackPatternSerializer
# Sharing Servers
from kraut_api.serializers import CollectionSerializer, ServersSerializer
#
from kraut_parser.utils import get_object_for_observable, get_related_objects_for_object
from kraut_incident.models import Contact, Handler, Incident
from kraut_intel.models import PackageComment, NamespaceIcon, ThreatActorComment, CampaignComment, TTPComment, IndicatorComment, ObservableComment
from kraut_sharing.models import TAXII_Remote_Server, TAXII_Remote_Collection
from kraut_sharing.forms import DiscoveryForm
from kraut_sharing.feed import CollectionRequest

import json, csv

################### PACKAGE #####################

@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def package_tree(request, pk):
    try:
        pack = Package.objects.get(pk=pk)
    except Package.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    response = {}
    nodes = []
    links = []
    used = {}
    node = {'id': pack.name, 'group': 1, 'type': 'package', 'score': 1, 'size': 20, 'dbid': pack.id}
    used[pack.id] = True
    nodes.append(node)
    node_counter = 1
    found_threatactors = False
    found_indicators = False
    for ta in pack.threat_actors.all():
        node = {'id': ta.name, 'group': 2, 'size': 10, 'type': 'threatactor', 'score': 0.7, 'dbid': ta.id}
        link = {'source': 0, 'target': node_counter, 'value': 1}
        nodes.append(node)
        links.append(link)
        ca_counter = node_counter + 1
        for camp in ta.campaigns.all():
            node = {'id': camp.name, 'group': 3, 'size': 10, 'type': 'campaigns', 'score': 0.5, 'dbid': camp.id}
            link = {'source': node_counter, 'target': ca_counter, 'value': 1}
            nodes.append(node)
            links.append(link)
            ca_counter += 1
        node_counter = ca_counter
        found_threatactors = True
    if not found_threatactors:
        for camp in pack.campaigns.all():
            node = {'id': camp.name, 'group': 3, 'size': 10, 'type': 'campaigns', 'score': 0.5, 'dbid': camp.id}
            link = {'source': 0, 'target': node_counter, 'value': 1}
            nodes.append(node)
            links.append(link)
            node_counter += 1
    for ind in pack.indicators.all():
        node = {'id': ind.name, 'group': 4, 'size': 10, 'type': 'indicator', 'score': 0.3, 'dbid': ind.id}
        link = {'source': 0, 'target': node_counter, 'value': 1}
        nodes.append(node)
        links.append(link)
        obs_counter = node_counter + 1
        for obs in ind.observable_set.all():
            node = {'id': obs.name, 'group': 5, 'size': 2, 'type': 'observable', 'score': 0.6, 'dbid': obs.id}
            link = {'source': node_counter, 'target': obs_counter, 'value': 1}
            nodes.append(node)
            links.append(link)
            obs_counter +=1
        node_counter = obs_counter
        found_indicators = True
    if not found_indicators:
        for obs in pack.observables.all():
            node = {'id': obs.name, 'group': 4, 'size': 10, 'type': 'observable', 'score': 0.6, 'dbid': obs.id}
            link = {'source': 0, 'target': node_counter, 'value': 1}
            nodes.append(node)
            links.append(link)
            if obs.package_set.count() > 0:
                opk_counter = node_counter + 1
                for opk in obs.package_set.all():
                    try:
                        v = used[opk.id]
                    except:
                        node = {'id': opk.name, 'group': 1, 'type': 'package', 'score': 1, 'size': 20, 'dbid': opk.id}
                        link = {'source': node_counter, 'target': opk_counter, 'value': 1}
                        nodes.append(node)
                        links.append(link)
                        opk_counter += 1
                        used[opk.id] = True
                node_counter = opk_counter
            else:
                node_counter += 1
    for ttp in pack.ttps.all():
        node = {'id': ttp.name, 'group': 4, 'size': 10, 'type': 'ttp', 'score': 0.8}
        link = {'source': 0, 'target': node_counter, 'value': 1}
        nodes.append(node)
        links.append(link)
        node_counter += 1
    response['nodes'] = nodes
    response['links'] = links
    return JsonResponse(response)

@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def package_quick(request, pk, otype, format=None):
    if not request.method == 'GET':
        return Response(status=status.HTTP_400_BAD_REQUEST)
    try:
        pack = Package.objects.get(pk=pk)
    except Package.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    if format and format=='csv':
        if otype == 'FileObjectType':
            fname = "hashes"
        else:
            fname = 'network-indicators'
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = 'attachment; filename="%s-%s.csv"' % (pack.package_id, fname)
        writer = csv.writer(response)
        for obs in pack.observables.all():
            if obs.observable_type == otype:
                objects = get_object_for_observable(observable_type=obs.observable_type, observable_object=obs, no_hash=False)
                for obj in objects:
                    writer.writerow(['%s' % (obj)])
        for ind in pack.indicators.all():
            for obs in ind.observable_set.all():
                if obs.observable_type == otype:
                    objects = get_object_for_observable(observable_type=obs.observable_type, observable_object=obs, no_hash=False)
                    for obj in objects:
                        writer.writerow(['%s' % (obj)])
        return response
    response = {'results': []}
    for obs in pack.observables.all():
        if obs.observable_type == otype:
            objects = get_object_for_observable(observable_type=obs.observable_type, observable_object=obs, no_hash=False)
            for obj in objects:
                item = {'value': '%s' % (obj)}
                if item not in response['results']:
                    response['results'].append(item)
    for ind in pack.indicators.all():
        for obs in ind.observable_set.all():
            if obs.observable_type == otype:
                objects = get_object_for_observable(observable_type=obs.observable_type, observable_object=obs, no_hash=False)
                for obj in objects:
                    item = {'value': '%s' % (obj)}
                    if item not in response['results']:
                        response['results'].append(item)
    return JsonResponse(response)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def package_list(request, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if order_by_column == 'short_name':
                    order_by_column = 'name'
                if order_by_column == 'namespace_icon':
                    order_by_column = 'namespace'
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_by_column = 'name'
                order_direction = '-'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        queryset = Package.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(namespace__namespace__istartswith=search_value)
            )
        #paginator = Paginator(queryset, max_items)
        #try:
        #    pack = paginator.page(page)
        #except:
        #    pack = paginator.page(1)
        pack = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = PackSerializer(instance=pack, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def package_detail(request, pk, format=None):
    try:
        pack = Package.objects.get(pk=pk)
    except Package.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    if request.method == 'GET':
        serializer = PackageSerializer(pack)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def package_detail_observables(request, pk, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_by_column = 'name'
                order_direction = '-'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        try:
            pack = Package.objects.get(pk=pk)
        except Package.DoesNotExist:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        queryset = pack.observables.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(observable_type__istartswith=search_value)
            )
        observables = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = ObsSerializer(instance=observables, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def package_detail_indicators(request, pk, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_direction = '-'
                order_by_column = 'name'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        try:
            pack = Package.objects.get(pk=pk)
        except Package.DoesNotExist:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        queryset = pack.indicators.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(indicator_types__itype__istartswith=search_value)|
                Q(confidence__value__istartswith=search_value)
            )
        indicators = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = Ind2Serializer(instance=indicators, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def package_detail_campaigns(request, pk, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_direction = '-'
                order_by_column = 'name'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        try:
            pack = Package.objects.get(pk=pk)
        except Package.DoesNotExist:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        queryset = pack.campaigns.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(status__istartswith=search_value)|
                Q(confidence__value__istartswith=search_value)
            )
        indicators = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = CampSerializer(instance=indicators, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def package_detail_ttps(request, pk, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_direction = '-'
                order_by_column = 'name'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        try:
            pack = Package.objects.get(pk=pk)
        except Package.DoesNotExist:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        queryset = pack.ttps.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(short_description__istartswith=search_value)
            )
        ttps = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = TTPSerializer(instance=ttps, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def package_detail_threatactors(request, pk, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_direction = '-'
                order_by_column = 'name'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        try:
            pack = Package.objects.get(pk=pk)
        except Package.DoesNotExist:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        queryset = pack.threat_actors.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(short_description__istartswith=search_value)
            )
        threatactors = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = ThreatActorSerializer(instance=threatactors, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



################### THREAT ACTOR #####################

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def threatactor_list(request, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if order_by_column == 'short_name':
                    order_by_column = 'name'
                if order_by_column == 'namespace_icon':
                    order_by_column = 'namespace'
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_by_column = 'name'
                order_direction = '-'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        queryset = ThreatActor.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(namespace__namespace__istartswith=search_value)
            )
        tas = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = TASerializer(instance=tas, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def threatactor_detail(request, pk, format=None):
    try:
        ta = ThreatActor.objects.get(pk=pk)
    except ThreatActor.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    if request.method == 'GET':
        serializer = ThreatActorSerializer(ta)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def threatactor_detail_campaigns(request, pk, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_by_column = 'name'
                order_direction = '-'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        try:
            ta = ThreatActor.objects.get(pk=pk)
        except ThreatActor.DoesNotExist:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        queryset = ta.campaigns.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(status__istartswith=search_value)|
                Q(confidence__value__istartswith=search_value)
            )
        campaigns = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = CampSerializer(instance=campaigns, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def threatactor_detail_associated_threatactors(request, pk, format=None):
    if not request.method == 'GET':
        return Response(status=status.HTTP_400_BAD_REQUEST)
    try:
        ta = ThreatActor.objects.get(pk=pk)
    except ThreatActor.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    response = {'results': []}
    for asta in ta.associated_threat_actors.all():
        response['results'].append({'name': asta.name, 'threatactor_id': asta.id})
    return JsonResponse(response)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def threatactor_detail_related_packages(request, pk, format=None):
    if not request.method == 'GET':
        return Response(status=status.HTTP_400_BAD_REQUEST)
    try:
        ta = ThreatActor.objects.get(pk=pk)
    except ThreatActor.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    final_list = []
    ### get for initial observable
    try:
        packages = Package.objects.filter(threat_actors=ta)
        for package in packages:
            pack_dict = {'id': package.pk, 'name': package.name}
            final_list.append(pack_dict)
    except Package.DoesNotExist:
        pass
    total_results = len(final_list)
    response = {
        'count': total_results,
        'iTotalRecords': total_results,
        'iTotalDisplayRecords': total_results,
        'results': final_list
    }
    return JsonResponse(response)


@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def threatactor_detail_observed_ttps(request, pk, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_direction = '-'
                order_by_column = 'name'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        try:
            ta = ThreatActor.objects.get(pk=pk)
        except ThreatActor.DoesNotExist:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        queryset = ta.observed_ttps.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(short_description__istartswith=search_value)
            )
        ttps = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = TTPSerializer(instance=ttps, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


################### TTPS #####################

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def ttp_list(request, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_direction = '-'
                order_by_column = 'name'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        queryset = TTP.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(short_description__istartswith=search_value)|
                Q(namespace__namespace__istartswith=search_value)|
                Q(ttp_id__icontains=search_value)
            )
        ttps = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = TTPSerializer(instance=ttps, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def ttp_related_ttps(request, pk, format=None):
    try:
        ttp = TTP.objects.get(pk=pk)
    except TTP.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    if request.method == 'GET':
        final_list = []
        try:
            relttps = RelatedTTP.objects.filter(from_ttp=ttp)
            for rel in relttps:
                rel_dict = {'id': rel.to_ttp.id, 'name': rel.to_ttp.name, 'relation': rel.relationship}
                final_list.append(rel_dict)
            relttps = RelatedTTP.objects.filter(to_ttp=ttp)
            for rel in relttps:
                rel_dict = {'id': rel.from_ttp.id, 'name': rel.from_ttp.name, 'relation': rel.relationship}
                final_list.append(rel_dict)
        except RelatedTTP.DoesNotExist:
            pass
        total_results = len(final_list)
        response = {
            'count': total_results,
            'iTotalRecords': total_results,
            'iTotalDisplayRecords': total_results,
            'results': final_list
        }
        return JsonResponse(response)
    return Response(status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def ttp_related_packages(request, pk, format=None):
    try:
        ttp = TTP.objects.get(pk=pk)
    except TTP.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    if request.method == 'GET':
        final_list = []
        try:
            packages = Package.objects.filter(ttps=ttp)
            for package in packages:
                pack_dict = {'id': package.pk, 'name': package.name}
                final_list.append(pack_dict)
        except Package.DoesNotExist:
            pass
        total_results = len(final_list)
        response = {
            'count': total_results,
            'iTotalRecords': total_results,
            'iTotalDisplayRecords': total_results,
            'results': final_list
        }
        return JsonResponse(response)
    return Response(status=status.HTTP_400_BAD_REQUEST)


################### MALWARE INSTANCES #####################

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def malware_instances_list(request, format=None):
    """ api function to list all malware instances
    """
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if order_by_column == 'short_name':
                    order_by_column = 'name'
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_direction = '-'
                order_by_column = 'name'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        queryset = MalwareInstance.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)
            )
        mwinstance = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = MalwareInstanceSerializer(instance=mwinstance, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def ttp_malware_instances(request, pk, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        try:
            ttp = TTP.objects.get(pk=pk)
        except TTP.DoestNotExist:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        queryset = ttp.malwareinstance_set.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(subname__istartswith=search_value)
            )
        mw = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = MalwareInstanceSerializer(instance=mw, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


################### ATTACK PATTERN #####################


@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def attack_patterns_list(request, format=None):
    """ api function to list all attack paterns
    """
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if order_by_column == 'short_name':
                    order_by_column = 'name'
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_direction = '-'
                order_by_column = 'name'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        queryset = AttackPattern.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)
            )
        atp = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = AttackPatternSerializer(instance=atp, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def ttp_attack_patterns(request, pk, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        try:
            ttp = TTP.objects.get(pk=pk)
        except TTP.DoestNotExist:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        queryset = ttp.attackpattern_set.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(description__istartswith=search_value)|
                Q(capec_id__icontains=search_value)
            )
        mw = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = AttackPatternSerializer(instance=mw, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



################### CAMPAIGN #####################

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def campaign_list(request, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if order_by_column == 'namespace_icon':
                    order_by_column = 'namespace'
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_direction = '-'
                order_by_column = 'name'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        queryset = Campaign.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(namespace__namespace__istartswith=search_value)
            )
        tas = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = CampSerializer(instance=tas, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def campaign_detail(request, pk, format=None):
    try:
        campaign = Campaign.objects.get(pk=pk)
    except Campaign.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    if request.method == 'GET':
        serializer = CampaignSerializer(campaign)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def campaign_detail_related_indicators(request, pk, format=None):
    if not request.method == 'GET':
        return Response(status=status.HTTP_400_BAD_REQUEST)
    try:
        campaign = Campaign.objects.get(pk=pk)
    except Campaign.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    response = {'results': []}
    for relindi in campaign.related_indicators.all():
        response['results'].append({'name': relindi.name, 'indicator_id': relindi.id})
    return JsonResponse(response)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def campaign_detail_associated_campaigns(request, pk, format=None):
    if not request.method == 'GET':
        return Response(status=status.HTTP_400_BAD_REQUEST)
    try:
        campaign = Campaign.objects.get(pk=pk)
    except Campaign.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    response = {'results': []}
    for assoc in campaign.associated_campaigns.all():
        response['results'].append({'name': assoc.name, 'campaign_id': assoc.id})
    return JsonResponse(response)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def campaign_detail_related_packages(request, pk, format=None):
    if not request.method == 'GET':
        return Response(status=status.HTTP_400_BAD_REQUEST)
    try:
        campaign = Campaign.objects.get(pk=pk)
    except Campaign.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    final_list = []
    ### get for initial observable
    try:
        packages = Package.objects.filter(campaigns=campaign)
        for package in packages:
            pack_dict = {'id': package.pk, 'name': package.name}
            final_list.append(pack_dict)
    except Package.DoesNotExist:
        pass
    total_results = len(final_list)
    response = {
        'count': total_results,
        'iTotalRecords': total_results,
        'iTotalDisplayRecords': total_results,
        'results': final_list
    }
    return JsonResponse(response)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def campaign_detail_related_ttps(request, pk, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_direction = '-'
                order_by_column = 'name'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        try:
            campaign = Campaign.objects.get(pk=pk)
        except Campaign.DoesNotExist:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        queryset = campaign.related_ttps.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(short_description__istartswith=search_value)
            )
        ttps = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = TTPSerializer(instance=ttps, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

################### INDICATOR #####################


@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def indicator_list(request, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if order_by_column == 'namespace_icon':
                    order_by_column = 'namespace'
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_direction = '-'
                order_by_column = 'name'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        queryset = Indicator.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(namespace__namespace__istartswith=search_value)|
                Q(indicator_id__contains=search_value)
            )
        tas = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = IndSerializer(instance=tas, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def indicator_detail(request, pk, format=None):
    try:
        indicator = Indicator.objects.get(pk=pk)
    except Indicator.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    if request.method == 'GET':
        serializer = IndicatorSerializer(indicator)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def indicator_detail_related_indicators(request, pk, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_direction = '-'
                order_by_column = 'name'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        try:
            indicator = Indicator.objects.get(pk=pk)
        except Indicator.DoesNotExist:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        queryset = indicator.related_indicators.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(indicator_types__itype__istartswith=search_value)|
                Q(confidence__value__istartswith=search_value)
            )
        indicators = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = Ind2Serializer(instance=indicators, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def indicator_detail_observables(request, pk, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_direction = '-'
                order_by_column = 'name'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        try:
            indicator = Indicator.objects.get(pk=pk)
        except Indicator.DoesNotExist:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        queryset = indicator.observable_set.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(observable_type__istartswith=search_value)
            )
        observables = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = ObservableSerializer(instance=observables, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def indicator_detail_ttps(request, pk, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_direction = '-'
                order_by_column = 'name'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        try:
            indicator = Indicator.objects.get(pk=pk)
        except Indicator.DoesNotExist:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        queryset = indicator.ttps.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(short_description__istartswith=search_value)
            )
        ttps = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = TTPSerializer(instance=ttps, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)


@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def indicator_detail_compositions(request, pk, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_direction = '-'
                order_by_column = 'name'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        try:
            indicator = Indicator.objects.get(pk=pk)
        except Indicator.DoesNotExist:
            return Response(status=status.HTTP_400_BAD_REQUEST)
        queryset = indicator.observablecomposition_set.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(operator__istartswith=search_value)
            )
        compositions = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = ObservableCompositionSerializer(instance=compositions, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)


@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def create_composition_json(composition, created):
    result = {'name': composition.name, 'operator': composition.operator, 'compositions': [], 'observables': []}
    for obs in composition.observables.all():
        result['observables'].append({'id': obs.id, 'name': obs.name, 'observable_type': obs.observable_type})
    for comp in composition.observable_compositions.all():
        if comp.name in created:
            continue
        created.append(comp.name)
        result['compositions'].append(create_composition_json(comp, created))
    return result

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def composition_details(request, pk, format=None):
    try:
        composition = ObservableComposition.objects.get(pk=pk)
    except ObservableComposition.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    response = {'name': composition.name, 'operator': composition.operator, 'compositions': [], 'observables': []}
    for obs in composition.observables.all():
        response['observables'].append({'id': obs.id, 'name': obs.name, 'observable_type': obs.observable_type})
    created = [composition.name]
    for comp in composition.observable_compositions.all():
        if comp.name in created:
            continue
        created.append(comp.name)
        response['compositions'].append(create_composition_json(comp, created))
    #return HttpResponse(json.dumps(response, sort_keys=True, indent=4), content_type="application/json")
    return JsonResponse(response)

@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def create_composition_json_d3(composition, created):
    result = {'name': composition.name+' -- Operator -- '+composition.operator, 'children': []}
    for obs in composition.observables.all():
        result['children'].append({'name': obs.name, 'size': 20, 'observable_id': obs.id, 'url': reverse('intel:observable',                     kwargs={'observable_id': obs.id})})
    for comp in composition.observable_compositions.all():
        if comp.name in created:
            continue
        created.append(comp.name)
        result['children'].append(create_composition_json_d3(comp, created))
    return result

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def composition_details_d3(request, pk, format=None):
    try:
        composition = ObservableComposition.objects.get(pk=pk)
    except ObservableComposition.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    response = {'name': composition.name+' -- Operator -- '+composition.operator, 'children': []}
    for obs in composition.observables.all():
        response['children'].append({'name': obs.name, 'size': 20, 'observable_id': obs.id, 'url': reverse('intel:observable', kwargs={'observable_id': obs.id})})
    created = [composition.name]
    for comp in composition.observable_compositions.all():
        if comp.name in created:
            continue
        created.append(comp.name)
        response['children'].append(create_composition_json_d3(comp, created))
    #return HttpResponse(json.dumps(response, sort_keys=False, indent=4), content_type="application/json")
    return JsonResponse(response)

################### OBSERVABLE #####################



@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def observable_list(request, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if order_by_column == 'short_name':
                    order_by_column = 'name'
                if order_by_column == 'namespace_icon':
                    order_by_column = 'namespace'
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_direction = '-'
                order_by_column = 'name'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'name'
            order_direction = '-'
            search_value = None
        # construct queryset
        queryset = Observable.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(observable_type__istartswith=search_value)|
                Q(namespace__namespace__istartswith=search_value)|
                Q(observable_id__icontains=search_value)
            )
        observables = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = ObsSerializer(instance=observables, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def observable_detail(request, pk, format=None):
    try:
        observable = Observable.objects.get(pk=pk)
    except Observable.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    if request.method == 'GET':
        serializer = ObservableSerializer(observable)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def observable_related_objects(request, pk, format=None):
    try:
        observable = Observable.objects.get(pk=pk)
    except Observable.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    if request.method == 'GET':
        objects = get_object_for_observable(observable_type=observable.observable_type, observable_object=observable)
        final_list = []
        covered = []
        for obj in objects:
            related_objects_list = get_related_objects_for_object(obj.id, observable.observable_type)
            for rel_obj_dict in related_objects_list:
                for rel_obj in rel_obj_dict['objects']:
                    rel_obs = []
                    for obs in rel_obj.observables.all():
                        if obs.id not in covered:
                            covered.append(obs.id)
                            rel_obs_dict = {'id': obs.id, 'name': str(obs), 'relation': rel_obj_dict['relation']}
                            rel_obs.append(rel_obs_dict)
                    final_list.extend(rel_obs)
        total_results = len(final_list)
        response = {
            'count': total_results,
            'iTotalRecords': total_results,
            'iTotalDisplayRecords': total_results,
            'results': final_list
        }
        return JsonResponse(response)
    return Response(status=status.HTTP_400_BAD_REQUEST)

@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def recurse_composition(item, test_list, done):
    for ind in item.indicator.all():
        ind_dict = {'id': ind.id, 'name': ind.name}
        if ind_dict not in test_list:
            test_list.append(ind_dict)
    for obs in item.observables.all():
        for ind in obs.indicators.all():
            ind_dict = {'id': ind.id, 'name': ind.name}
            if ind_dict not in test_list:
                test_list.append(ind_dict)
    for comp in item.observable_compositions.all():
        if comp.name not in done:
            done.append(comp.name)
            recurse_composition(comp, test_list, done)
    return test_list

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def observable_related_indicators(request, pk, format=None):
    try:
        observable = Observable.objects.get(pk=pk)
    except Observable.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    if request.method == 'GET':
        final_list = []
        done = []
        for indicator_item in observable.indicators.all():
            indicator_dict = {'id': indicator_item.id, 'name': indicator_item.name}
            final_list.append(indicator_dict)
        for obs_comp in observable.observablecomposition_set.all():
            recurse_composition(obs_comp, final_list, done)

        total_results = len(final_list)
        response = {
            'count': total_results,
            'iTotalRecords': total_results,
            'iTotalDisplayRecords': total_results,
            'results': final_list
        }
        return JsonResponse(response)
    return Response(status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def observable_related_packages(request, pk, format=None):
    try:
        observable = Observable.objects.get(pk=pk)
    except Observable.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    if request.method == 'GET':
        final_list = []
        ### get for initial observable
        try:
            packages = Package.objects.filter(observables=observable)
            for package in packages:
                pack_dict = {'id': package.pk, 'name': package.name}
                final_list.append(pack_dict)
        except Package.DoesNotExist:
            pass
        ### check if object in other observables
        if observable.observable_type == 'CompositionContainer':
            for comp in observable.compositions.all():
                for obser in comp.observables.all():
                    objects = get_object_for_observable(observable_type=obser.observable_type, observable_object=obser)
                    for obj in objects:
                        for obs in obj.observables.all():
                            try:
                                packages = Package.objects.filter(observables=obs)
                            except Package.DoesNotExist:
                                continue
                        for package in packages:
                            pack_dict = {'id': package.pk, 'name': package.name}
                            if pack_dict not in final_list:
                                final_list.append(pack_dict)
        else:
            objects = get_object_for_observable(observable_type=observable.observable_type, observable_object=observable)
            for obj in objects:
                for obs in obj.observables.all():
                    try:
                        packages = Package.objects.filter(observables=obs)
                    except Package.DoesNotExist:
                        continue
                    for package in packages:
                        pack_dict = {'id': package.pk, 'name': package.name}
                        if pack_dict not in final_list:
                            final_list.append(pack_dict)
        # check if observable belongs to indicator that is embedded in a package
        for indicator in observable.indicators.all():
            for package in indicator.package_set.all():
                pack_dict = {'id': package.pk, 'name': package.name}
                if pack_dict not in final_list:
                    final_list.append(pack_dict)
        # display results
        total_results = len(final_list)
        response = {
            'count': total_results,
            'iTotalRecords': total_results,
            'iTotalDisplayRecords': total_results,
            'results': final_list
        }
        return JsonResponse(response)
    return Response(status=status.HTTP_400_BAD_REQUEST)


################### OBJECTS #####################

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def object_get_observables(request, object_id, object_type):
    """Return a list of observables that contain the given object
    """
    final_list = []
    objects = get_object_for_observable(observable_type=object_type, object_id=object_id)
    for obj in objects:
        for obs in obj.observables.all():
            obs_dict = {'id': obs.pk, 'name': obs.name}
            if obs_dict not in final_list:
                final_list.append(obs_dict)
    total_results = len(final_list)
    response = {
        'count': total_results,
        'iTotalRecords': total_results,
        'iTotalDisplayRecords': total_results,
        'results': final_list
    }
    return JsonResponse(response)


@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def object_get_packages(request, object_id, object_type):
    """Return a list of intelligence packages that contain the given object
    """
    final_list = []
    objects = get_object_for_observable(observable_type=object_type, object_id=object_id)
    for obj in objects:
        for obs in obj.observables.all():
            try:
                packages = Package.objects.filter(observables=obs)
            except Package.DoesNotExist:
                continue
            for package in packages:
                pack_dict = {'id': package.pk, 'name': package.name}
                final_list.append(pack_dict)
    total_results = len(final_list)
    response = {
        'count': total_results,
        'iTotalRecords': total_results,
        'iTotalDisplayRecords': total_results,
        'results': final_list
    }
    return JsonResponse(response)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def object_ip_list(request, format=None):
    """Return a list of IP addresses
    """
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_by_column = 'address_value'
                order_direction = '-'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'address_value'
            order_direction = '-'
            search_value = None
        # construct queryset
        queryset = Address_Object.objects.filter(Q(category='ipv4-addr')|Q(category='ipv4-net')).order_by('-observables__last_modified')
        if search_value:
            queryset = queryset.filter(
                Q(address_value__icontains=search_value)|
                Q(category__icontains=search_value)
            )
        handler = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = AddressObjectSerializer(instance=handler, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def object_hash_list(request, format=None):
    """Return a list of file hashes
    """
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_by_column = 'md5_hash'
                order_direction = '-'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'md5_hash'
            order_direction = '-'
            search_value = None
        # construct queryset
        queryset = File_Object.objects.filter(~Q(md5_hash='No MD5')).order_by('-observables__last_modified')
        if search_value:
            queryset = queryset.filter(
                Q(md5_hash__icontains=search_value)|
                Q(sha256_hash__icontains=search_value)
            )
        handler = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = FileObjectSerializer(instance=handler, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def object_domain_list(request, format=None):
    """Return a list of domains
    """
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_by_column = 'uri_value'
                order_direction = '-'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'uri_value'
            order_direction = '-'
            search_value = None
        # construct queryset
        queryset = URI_Object.objects.all().order_by('-observables__last_modified')
        if search_value:
            queryset = queryset.filter(
                Q(uri_value__icontains=search_value)|
                Q(uri_type__icontains=search_value)
            )
        handler = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = URIObjectSerializer(instance=handler, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


################### INCIDENT HANDLER #####################

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def handler_list(request, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_by_column = 'lastname'
                order_direction = '-'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'lastname'
            order_direction = '-'
            search_value = None
        # construct queryset
        queryset = Handler.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(firstname__istartswith=search_value)|
                Q(lastname__istartswith=search_value)
            )
        handler = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = HandlerSerializer(instance=handler, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


################### INCIDENT CONTACTS #####################

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def contact_list(request, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_by_column = 'lastname'
                order_direction = '-'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'lastname'
            order_direction = '-'
            search_value = None
        # construct queryset
        queryset = Contact.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(firstname__istartswith=search_value)|
                Q(lastname__istartswith=search_value)
            )
        handler = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = ContactSerializer(instance=handler, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

################### INCIDENTS #####################

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def incident_list(request, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            # number of items to retrieve
            if 'length' in request.query_params:
                max_items = int(request.query_params['length'])
            # page to show
            if 'start' in request.query_params:
                page = int(int(request.query_params['start'])/int(max_items))+1
            # order
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_by_column = 'creation_time'
                order_direction = '-'
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'creation_time'
            order_direction = '-'
            search_value = None
        # construct queryset
        queryset = Incident.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(incident_number__icontains=search_value)|
                Q(title__icontains=search_value)|
                Q(status__name__istartswith=search_value)|
                Q(category__name__icontains=search_value)
            )
        incident = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = IncidentSerializer(instance=incident, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

################### SHARING #####################

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def taxii_server_list(request, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            if 'length' in request.query_params: max_items = int(request.query_params['length'])
            if 'start' in request.query_params: page = int(int(request.query_params['start'])/int(max_items))+1
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_by_column = 'creation_time'
                order_direction = '-'
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'creation_time'
            order_direction = '-'
            search_value = None
        queryset = TAXII_Remote_Server.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)|
                Q(host__icontains=search_value)
            )
        servers = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = ServersSerializer(instance=servers, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def taxii_collection_list(request, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            if 'length' in request.query_params: max_items = int(request.query_params['length'])
            if 'start' in request.query_params: page = int(int(request.query_params['start'])/int(max_items))+1
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_by_column = 'creation_time'
                order_direction = '-'
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'creation_time'
            order_direction = '-'
            search_value = None
        queryset = TAXII_Remote_Collection.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(name__icontains=search_value)
            )
        collections = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        serializer = CollectionSerializer(instance=collections, context=serializer_context, many=True)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['POST'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def taxii_feed_information(request, format=None):
    if not request.method == 'POST':
        return HttpResponse(status=status.HTTP_400_BAD_REQUEST)
    discovery_form = DiscoveryForm(request.POST)
    if discovery_form.is_valid():
        discovery_url = discovery_form.cleaned_data['url']
        script = CollectionRequest(discovery_url)
        result = script.run()
        response = {'results': []}
        for item in  result['collection_informations']:
            if 'available' in item and item['available']:
                entry = {'name': item['collection_name'], 'address': item['polling_service_instances'][0]['poll_address'], 'type': item['collection_type']}
                response['results'].append(entry)
        return JsonResponse(response)
    else:
        script = CollectionRequest('http://hailataxii.com/taxii-discovery-service/')
        result = script.run()
        response = {'results': []}
        for item in  result['collection_informations']:
            if 'available' in item and item['available']:
                entry = {'name': item['collection_name'], 'address': item['polling_service_instances'][0]['poll_address'], 'type': item['collection_type']}
                response['results'].append(entry)
        return HttpResponse(json.dumps(response), content_type="application/json")
    return HttpResponse(status=status.HTTP_400_BAD_REQUEST)

################### COMMENTS #####################

@api_view(['GET'])
@authentication_classes((SessionAuthentication, ))
@permission_classes((IsAuthenticated,))
def list_comments(request, object_type, format=None):
    if request.method == 'GET':
        paginator = CustomPaginator()
        max_items = 10
        page = request.query_params.get('page')
        if request.query_params:
            if 'length' in request.query_params: max_items = int(request.query_params['length'])
            if 'start' in request.query_params: page = int(int(request.query_params['start'])/int(max_items))+1
            if 'order[0][column]' in request.query_params and 'order[0][dir]' in request.query_params:
                order_by_column = request.query_params['columns['+str(request.query_params['order[0][column]'])+'][data]']
                if request.query_params['order[0][dir]'] == 'desc':
                    order_direction = '-'
                else:
                    order_direction = ''
            else:
                order_by_column = 'creation_time'
                order_direction = '-'
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            else:
                search_value = None
        else:
            order_by_column = 'creation_time'
            order_direction = '-'
            search_value = None
        if object_type == 'threatactors':
            queryset = ThreatActorComment.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        elif object_type == 'packages':
            queryset = PackageComment.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        elif object_type == 'campaigns':
            queryset = CampaignComment.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        elif object_type == 'ttps':
            queryset = TTPComment.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        elif object_type == 'indicators':
            queryset = IndicatorComment.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        elif object_type == 'observables':
            queryset = ObservableComment.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        else:
            queryset = PackageComment.objects.all().order_by('%s%s' % (order_direction, order_by_column))
        if search_value:
            queryset = queryset.filter(
                Q(ctext__icontains=search_value)
            )
        comments = paginator.paginate_queryset(queryset, request)
        serializer_context = {'request': request}
        if object_type == 'threatactors':
            serializer = ActorCommentSerializer(instance=comments, context=serializer_context, many=True)
            return paginator.get_paginated_response(serializer.data)
        elif object_type == 'packages':
            serializer = PackageCommentSerializer(instance=comments, context=serializer_context, many=True)
            return paginator.get_paginated_response(serializer.data)
        elif object_type == 'campaigns':
            serializer = CampaignCommentSerializer(instance=comments, context=serializer_context, many=True)
            return paginator.get_paginated_response(serializer.data)
        elif object_type == 'ttps':
            serializer = TTPCommentSerializer(instance=comments, context=serializer_context, many=True)
            return paginator.get_paginated_response(serializer.data)
        elif object_type == 'indicators':
            serializer = IndicatorCommentSerializer(instance=comments, context=serializer_context, many=True)
            return paginator.get_paginated_response(serializer.data)
        elif object_type == 'observables':
            serializer = ObservableCommentSerializer(instance=comments, context=serializer_context, many=True)
            return paginator.get_paginated_response(serializer.data)
        else:
            serializer = PackageCommentSerializer(instance=comments, context=serializer_context, many=True)
            return paginator.get_paginated_response(serializer.data)
        return paginator.get_paginated_response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
