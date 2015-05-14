# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.http import HttpResponse, HttpResponseNotFound

from kraut_parser.models import Observable
from kraut_parser.utils import get_object_for_observable

from kraut_export.utils import cybox_file, cybox_address, cybox_uri, cybox_http

# Create your views here.

def cybox_observable(request, pk):
    try:
        observable = Observable.objects.get(pk=pk)
    except Observable.DoesNotExist:
        return HttpResponseNotFound("Observable not found!")
    objects = get_object_for_observable(observable.observable_type, observable)
    cybox_xml = None
    if observable.observable_type == 'FileObjectType':
        cybox_xml = cybox_file(observable, observable.observable_type, objects)
    elif observable.observable_type == 'AddressObjectType':
        cybox_xml = cybox_address(observable, observable.observable_type, objects)
    elif observable.observable_type == 'URIObjectType':
        cybox_xml = cybox_uri(observable, observable.observable_type, objects)
    elif observable.observable_type == 'HTTPSessionObjectType':
        cybox_xml = cybox_http(observable, observable.observable_type, objects)
    ### MISSING
    # MutexObjectType
    # CodeObjectType
    # WindowsDriverObjectType
    # LinkObjectType
    # WindowsRegistryKeyObjectType
    # EmailMessageObjectType
    # DNSQueryObjectType
    if cybox_xml:
        return HttpResponse(cybox_xml.to_xml(), content_type="text/xml")
    return HttpResponseNotFound("Object %s not handled!" % (observable.observable_type))
