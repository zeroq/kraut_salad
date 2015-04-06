# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.http import JsonResponse
from django.db.models import Q
from django.core.paginator import Paginator
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from kraut_parser.models import Indicator, Observable, Campaign, ThreatActor, Package
from kraut_api.serializers import IndicatorSerializer, PaginatedIndicatorSerializer, ObservableSerializer, PaginatedObservableSerializer, CampaignSerializer, PaginatedCampaignSerializer, ThreatActorSerializer, PaginatedThreatActorSerializer, PackageSerializer, PaginatedPackageSerializer, PaginatedIndicator2Serializer
from kraut_parser.utils import get_object_for_observable, get_related_objects_for_object

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

    response['nodes'] = nodes
    response['links'] = links
    return JsonResponse(response)

def package_quick(request, pk, otype):
    if not request.method == 'GET':
        return Response(status=status.HTTP_400_BAD_REQUEST)
    try:
        pack = Package.objects.get(pk=pk)
    except Package.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    response = {'results': []}
    for obs in pack.observables.all():
        if obs.observable_type == otype:
            objects = get_object_for_observable(obs.observable_type, obs, no_hash=False)
            for obj in objects:
                response['results'].append({'value': '%s' % (obj)})
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
        objects = get_object_for_observable(observable.observable_type, observable)
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

