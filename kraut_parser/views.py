from django.core.paginator import Paginator
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from kraut_parser.models import Indicator, Observable
from kraut_parser.serializers import IndicatorSerializer, PaginatedIndicatorSerializer, ObservableSerializer, PaginatedObservableSerializer

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
        queryset = Observable.objects.all()
        paginator = Paginator(queryset, 20)
        page = request.QUERY_PARAMS.get('page')
        try:
            observables = paginator.page(page)
        except:
            observables = paginator.page(1)
        serializer_context = {'request': request}
        serializer = PaginatedObservableSerializer(observables, context=serializer_context)
        return Response(serializer.data)
    return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
