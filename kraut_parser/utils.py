# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from kraut_parser.models import File_Object, HTTPSession_Object, URI_Object

def get_object_for_observable(observable_type, observable_object, no_hash=True):
    return_list = []
    if observable_type == 'FileObjectType':
        for obj in File_Object.objects.filter(observables=observable_object):
            if no_hash:
                return_list.append(obj)
            else:
                if (obj.md5_hash and obj.md5_hash != 'No MD5') or (obj.sha256_hash and obj.sha256_hash != 'No SHA256'):
                    return_list.append(obj)
    elif observable_type == 'HTTPSessionObjectType':
        for obj in HTTPSession_Object.objects.filter(observables=observable_object):
            return_list.append(obj)
    elif observable_type == 'URIObjectType':
        for obj in URI_Object.objects.filter(observables=observable_object):
            return_list.append(obj)

    return return_list
