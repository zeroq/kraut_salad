# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.http import JsonResponse, HttpResponse
from django.core.urlresolvers import reverse
from django.db.models import Q
from django.core.paginator import Paginator
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from kraut_parser.models import Indicator, Observable, Campaign, ThreatActor, Package, ObservableComposition, File_Object
from kraut_api.serializers import IndicatorSerializer, PaginatedIndicatorSerializer, ObservableSerializer, PaginatedObservableSerializer, CampaignSerializer, PaginatedCampaignSerializer, ThreatActorSerializer, PaginatedThreatActorSerializer, PackageSerializer, PaginatedPackageSerializer, PaginatedIndicator2Serializer, PaginatedCompositionSerializer, PaginatedContactSerializer, PaginatedHandlerSerializer, PaginatedFileObjectSerializer, PaginatedIncidentSerializer
from kraut_parser.utils import get_object_for_observable, get_related_objects_for_object
from kraut_incident.models import Contact, Handler, Incident

import json, csv

################### PACKAGE #####################

def package_tree(request, pk):
    try:
        pack = Package.objects.get(pk=pk)
    except Package.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    response = {}
    nodes = []
    links = []
    node = {'id': pack.name, 'group': 1, 'type': 'package', 'score': 1, 'size': 20}
    nodes.append(node)
    node_counter = 1
    found_threatactors = False
    found_indicators = False
    for ta in pack.threat_actors.all():
        node = {'id': ta.name, 'group': 2, 'size': 10, 'type': 'threatactor', 'score': 0.7}
        link = {'source': 0, 'target': node_counter, 'value': 1}
        nodes.append(node)
        links.append(link)
        ca_counter = node_counter + 1
        for camp in ta.campaigns.all():
            node = {'id': camp.name, 'group': 3, 'size': 10, 'type': 'campaigns', 'score': 0.5}
            link = {'source': node_counter, 'target': ca_counter, 'value': 1}
            nodes.append(node)
            links.append(link)
            ca_counter += 1
        node_counter = ca_counter
        found_threatactors = True
    if not found_threatactors:
        for camp in pack.campaigns.all():
            node = {'id': camp.name, 'group': 3, 'size': 10, 'type': 'campaigns', 'score': 0.5}
            link = {'source': 0, 'target': node_counter, 'value': 1}
            nodes.append(node)
            links.append(link)
            node_counter += 1
    for ind in pack.indicators.all():
        node = {'id': ind.name, 'group': 4, 'size': 10, 'type': 'indicator', 'score': 0.3}
        link = {'source': 0, 'target': node_counter, 'value': 1}
        nodes.append(node)
        links.append(link)
        obs_counter = node_counter + 1
        for obs in ind.observable_set.all():
            node = {'id': obs.name, 'group': 5, 'size': 2, 'type': 'observable', 'score': 0.6}
            link = {'source': node_counter, 'target': obs_counter, 'value': 1}
            nodes.append(node)
            links.append(link)
            obs_counter +=1
        node_counter = obs_counter
        found_indicators = True
    if not found_indicators:
        for obs in pack.observables.all():
            node = {'id': obs.name, 'group': 4, 'size': 10, 'type': 'observable', 'score': 0.6}
            link = {'source': 0, 'target': node_counter, 'value': 1}
            nodes.append(node)
            links.append(link)
            node_counter += 1
    response['nodes'] = nodes
    response['links'] = links
    return JsonResponse(response)

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
        return response
    response = {'results': []}
    for obs in pack.observables.all():
        if obs.observable_type == otype:
            objects = get_object_for_observable(observable_type=obs.observable_type, observable_object=obs, no_hash=False)
            for obj in objects:
                item = {'value': '%s' % (obj)}
                if item not in response['results']:
                    response['results'].append(item)
    return JsonResponse(response)

@api_view(['GET'])
def package_list(request, format=None):
    if request.method == 'GET':
        max_items = 10
        page = request.QUERY_PARAMS.get('page')
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
                Q(name__istartswith=search_value)|
                Q(namespace__istartswith=search_value)
            )
        paginator = Paginator(queryset, max_items)
        try:
            pack = paginator.page(page)
        except:
            pack = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedPackageSerializer(pack, context=serializer_context)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
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
def package_detail_observables(request, pk, format=None):
    if request.method == 'GET':
        max_items = 10
        page = request.QUERY_PARAMS.get('page')
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
                Q(name__istartswith=search_value)|
                Q(observable_type__istartswith=search_value)
            )
        paginator = Paginator(queryset, max_items)
        try:
            observables = paginator.page(page)
        except:
            observables = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedObservableSerializer(observables, context=serializer_context)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def package_detail_indicators(request, pk, format=None):
    if request.method == 'GET':
        max_items = 10
        page = request.QUERY_PARAMS.get('page')
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
                Q(name__istartswith=search_value)|
                Q(indicator_types__itype__istartswith=search_value)|
                Q(confidence__value__istartswith=search_value)
            )
        paginator = Paginator(queryset, max_items)
        try:
            indicators = paginator.page(page)
        except:
            indicators = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedIndicator2Serializer(indicators, context=serializer_context)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def package_detail_campaigns(request, pk, format=None):
    if request.method == 'GET':
        max_items = 10
        page = request.QUERY_PARAMS.get('page')
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
                Q(name__istartswith=search_value)|
                Q(status__istartswith=search_value)|
                Q(confidence__value__istartswith=search_value)
            )
        paginator = Paginator(queryset, max_items)
        try:
            indicators = paginator.page(page)
        except:
            indicators = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedCampaignSerializer(indicators, context=serializer_context)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def package_detail_threatactors(request, pk, format=None):
    if request.method == 'GET':
        max_items = 10
        page = request.QUERY_PARAMS.get('page')
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
                Q(name__istartswith=search_value)|
                Q(short_description__istartswith=search_value)
            )
        paginator = Paginator(queryset, max_items)
        try:
            indicators = paginator.page(page)
        except:
            indicators = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedThreatActorSerializer(indicators, context=serializer_context)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)



################### THREAT ACTOR #####################

@api_view(['GET'])
def threatactor_list(request, format=None):
    if request.method == 'GET':
        max_items = 10
        page = request.QUERY_PARAMS.get('page')
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
                Q(name__istartswith=search_value)|
                Q(namespace__istartswith=search_value)
            )
        paginator = Paginator(queryset, max_items)
        try:
            tas = paginator.page(page)
        except:
            tas = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedThreatActorSerializer(tas, context=serializer_context)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
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
def threatactor_detail_campaigns(request, pk, format=None):
    if request.method == 'GET':
        max_items = 10
        page = request.QUERY_PARAMS.get('page')
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
                Q(name__istartswith=search_value)|
                Q(status__istartswith=search_value)|
                Q(confidence__value__istartswith=search_value)
            )
        paginator = Paginator(queryset, max_items)
        try:
            campaigns = paginator.page(page)
        except:
            campaigns = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedCampaignSerializer(campaigns, context=serializer_context)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

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

################### CAMPAIGN #####################


@api_view(['GET'])
def campaign_list(request, format=None):
    if request.method == 'GET':
        max_items = 10
        page = request.QUERY_PARAMS.get('page')
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
                Q(name__istartswith=search_value)|
                Q(namespace__istartswith=search_value)
            )
        paginator = Paginator(queryset, max_items)
        try:
            tas = paginator.page(page)
        except:
            tas = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedCampaignSerializer(tas, context=serializer_context)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
def campaign_detail(request, pk, format=None):
    try:
        campaign = Campaign.objects.get(pk=pk)
    except Campaign.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    if request.method == 'GET':
        serializer = CampaignSerializer(campaign)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

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

################### INDICATOR #####################


@api_view(['GET'])
def indicator_list(request, format=None):
    if request.method == 'GET':
        max_items = 10
        page = request.QUERY_PARAMS.get('page')
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
                Q(name__istartswith=search_value)|
                Q(namespace__istartswith=search_value)
            )
        paginator = Paginator(queryset, max_items)
        try:
            tas = paginator.page(page)
        except:
            tas = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedIndicatorSerializer(tas, context=serializer_context)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


@api_view(['GET'])
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
def indicator_detail_related_indicators(request, pk, format=None):
    if request.method == 'GET':
        max_items = 10
        page = request.QUERY_PARAMS.get('page')
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
                Q(name__istartswith=search_value)|
                Q(indicator_types__itype__istartswith=search_value)|
                Q(confidence__value__istartswith=search_value)
            )
        paginator = Paginator(queryset, max_items)
        try:
            indicators = paginator.page(page)
        except:
            indicators = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedIndicator2Serializer(indicators, context=serializer_context)
        return Response(serializer.data)

@api_view(['GET'])
def indicator_detail_observables(request, pk, format=None):
    if request.method == 'GET':
        max_items = 10
        page = request.QUERY_PARAMS.get('page')
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
                Q(name__istartswith=search_value)|
                Q(observable_type__istartswith=search_value)
            )
        paginator = Paginator(queryset, max_items)
        try:
            observables = paginator.page(page)
        except:
            observables = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedObservableSerializer(observables, context=serializer_context)
        return Response(serializer.data)

@api_view(['GET'])
def indicator_detail_compositions(request, pk, format=None):
    if request.method == 'GET':
        max_items = 10
        page = request.QUERY_PARAMS.get('page')
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
                Q(name__istartswith=search_value)|
                Q(operator__istartswith=search_value)
            )
        paginator = Paginator(queryset, max_items)
        try:
            compositions = paginator.page(page)
        except:
            compositions = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedCompositionSerializer(compositions, context=serializer_context)
        return Response(serializer.data)


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
def observable_list(request, format=None):
    if request.method == 'GET':
        max_items = 10
        page = request.QUERY_PARAMS.get('page')
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
                Q(name__istartswith=search_value)|
                Q(observable_type__istartswith=search_value)|
                Q(namespace__istartswith=search_value)
            )
        paginator = Paginator(queryset, max_items)
        try:
            observables = paginator.page(page)
        except:
            observables = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedObservableSerializer(observables, context=serializer_context)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

@api_view(['GET'])
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



################### OBJECTS #####################

@api_view(['GET'])
def object_get_observables(request, object_id, object_type):
    """Return a list of observables that contain the given object
    """
    final_list = []
    objects = get_object_for_observable(observable_type=object_type, object_id=object_id)
    print objects
    for obj in objects:
        for obs in obj.observables.all():
            obs_dict = {'id': obs.pk, 'name': obs.name}
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
def object_hash_list(request, format=None):
    if request.method == 'GET':
        max_items = 10
        page = request.QUERY_PARAMS.get('page')
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
        queryset = File_Object.objects.filter(~Q(md5_hash='No MD5')).order_by('-observables__last_modified')
        if search_value:
            queryset = queryset.filter(
                Q(md5_hash__icontains=search_value)|
                Q(sha256_hash__icontains=search_value)
            )
        paginator = Paginator(queryset, max_items)
        try:
            handler = paginator.page(page)
        except:
            handler = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedFileObjectSerializer(handler, context=serializer_context)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


################### INCIDENT HANDLER #####################

@api_view(['GET'])
def handler_list(request, format=None):
    if request.method == 'GET':
        max_items = 10
        page = request.QUERY_PARAMS.get('page')
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
        paginator = Paginator(queryset, max_items)
        try:
            handler = paginator.page(page)
        except:
            handler = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedHandlerSerializer(handler, context=serializer_context)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


################### INCIDENT CONTACTS #####################

@api_view(['GET'])
def contact_list(request, format=None):
    if request.method == 'GET':
        max_items = 10
        page = request.QUERY_PARAMS.get('page')
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
        paginator = Paginator(queryset, max_items)
        try:
            contact = paginator.page(page)
        except:
            contact = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedContactSerializer(contact, context=serializer_context)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

################### INCIDENTS #####################

@api_view(['GET'])
def incident_list(request, format=None):
    if request.method == 'GET':
        max_items = 10
        page = request.QUERY_PARAMS.get('page')
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
                Q(status__istartswith=search_value)|
                Q(category__icontains=search_value)
            )
        paginator = Paginator(queryset, max_items)
        try:
            incident = paginator.page(page)
        except:
            incident = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedIncidentSerializer(incident, context=serializer_context)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

################### INCIDENTS #####################

