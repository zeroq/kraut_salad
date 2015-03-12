# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.db.models import Q
from django.core.paginator import Paginator
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from kraut_parser.models import Indicator, Observable, Campaign, ThreatActor, Package
from kraut_api.serializers import IndicatorSerializer, PaginatedIndicatorSerializer, ObservableSerializer, PaginatedObservableSerializer, CampaignSerializer, PaginatedCampaignSerializer, ThreatActorSerializer, PaginatedThreatActorSerializer, PackageSerializer, PaginatedPackageSerializer

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
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
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
def threatactor_list(request, format=None):
    if request.method == 'GET':
        queryset = ThreatActor.objects.all()
        paginator = Paginator(queryset, 20)
        page = request.QUERY_PARAMS.get('page')
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
def campaign_list(request, format=None):
    if request.method == 'GET':
        queryset = Campaign.objects.all()
        paginator = Paginator(queryset, 20)
        page = request.QUERY_PARAMS.get('page')
        try:
            campaigns = paginator.page(page)
        except:
            campaigns = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedCampaignSerializer(campaigns, context=serializer_context)
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

@api_view(['GET'])
def indicator_list(request, format=None):
    if request.method == 'GET':
        queryset = Indicator.objects.all()
        paginator = Paginator(queryset, 20)
        page = request.QUERY_PARAMS.get('page')
        try:
            indicators = paginator.page(page)
        except:
            indicators = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedIndicatorSerializer(indicators, context=serializer_context)
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
            # search
            if 'search[value]' in request.query_params:
                search_value = request.query_params['search[value]']
            # DEBUG
            for item in request.query_params:
                print item + ' - ' + request.query_params[item]
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
