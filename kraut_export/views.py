# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from rest_framework.response import Response
from django.http import JsonResponse, HttpResponse
from rest_framework import status

from kraut_parser.models import Observable
from kraut_parser.utils import get_object_for_observable

from kraut_export.utils import cybox_file

# Create your views here.

def cybox_observable(request, pk):
    try:
        observable = Observable.objects.get(pk=pk)
    except Observable.DoesNotExist:
        return Response(status=status.HTTP_400_BAD_REQUEST)
    objects = get_object_for_observable(observable.observable_type, observable)
    cybox_xml = None
    if observable.observable_type == 'FileObjectType':
        cybox_xml = cybox_file(observable, observable.observable_type, objects)
    if cybox_xml:
        return HttpResponse(cybox_xml.to_xml(), content_type="text/xml")
    return Response(status=status.HTTP_400_BAD_REQUEST)
