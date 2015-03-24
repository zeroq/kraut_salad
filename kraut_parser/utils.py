# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from kraut_parser.models import File_Object, HTTPSession_Object

def get_object_for_observable(observable_type, observable_object):
    return_list = []
    if observable_type == 'FileObjectType':
        for fobj in File_Object.objects.filter(observables=observable_object):
            child = {'name': fobj.md5_hash, 'children': []}
            for meta in fobj.file_meta.all():
                child['children'].append({'name': meta.file_name, 'size': 5})
            return_list.append(child)
    elif observable_type == 'HTTPSessionObjectType':
        for hobj in HTTPSession_Object.objects.filter(observables=observable_object):
            #child = {'name': hobj.client_request.domain_name.uri_value+hobj.client_request.request_uri, 'size': 5}
            child = {'name': hobj.client_request.request_uri, 'size': 5}
            #child = {'name': hobj.client_request.domain_name.uri_value, 'size': 5}
            return_list.append(child)
    else:
        child = {'name': observable_object.name, 'size': 5}
        return_list.append(child)
    return return_list
