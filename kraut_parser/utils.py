# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.db.models import Q
from kraut_parser.models import File_Object, HTTPSession_Object, URI_Object, Related_Object, Address_Object, Mutex_Object, Code_Object, EmailMessage_Object, Win_Registry_Object, DNSQuery_Object, Driver_Object, Link_Object

def get_object_for_observable(observable_type, observable_object=None, object_id=None, no_hash=True):
    """ Return the list of objects belonging to a given observable or the object for a given id.
        The optional no_hash parameter determines if also file objects without a hash should be returned.

        TODO: support all observable types that are implemented!
    """
    return_list = []
    # create filter
    if observable_object:
        q_filter = Q(observables=observable_object)
    elif object_id:
        q_filter = Q(id=object_id)
    else:
        q_filter = Q(observables=observable_object)|Q(id=object_id)
    # check observable type and query
    if observable_type == 'FileObjectType':
        for obj in File_Object.objects.filter(q_filter):
            if no_hash:
                return_list.append(obj)
            else:
                if (obj.md5_hash and obj.md5_hash != 'No MD5') or (obj.sha256_hash and obj.sha256_hash != 'No SHA256'):
                    return_list.append(obj)
    elif observable_type == 'HTTPSessionObjectType':
        for obj in HTTPSession_Object.objects.filter(q_filter):
            return_list.append(obj)
    elif observable_type == 'URIObjectType':
        for obj in URI_Object.objects.filter(q_filter):
            return_list.append(obj)
    elif observable_type == 'AddressObjectType':
        for obj in Address_Object.objects.filter(q_filter):
            return_list.append(obj)
    elif observable_type == 'MutexObjectType':
        for obj in Mutex_Object.objects.filter(q_filter):
            return_list.append(obj)
    elif observable_type == 'CodeObjectType':
        for obj in Code_Object.objects.filter(q_filter):
            return_list.append(obj)
    elif observable_type == 'EmailMessageObjectType':
        for obj in EmailMessage_Object.objects.filter(q_filter):
            return_list.append(obj)
    elif observable_type == 'WindowsRegistryKeyObjectType':
        for obj in Win_Registry_Object.objects.filter(q_filter):
            return_list.append(obj)
    elif observable_type == 'DNSQueryObjectType':
        for obj in DNSQuery_Object.objects.filter(q_filter):
            return_list.append(obj)
    elif observable_type == 'WindowsDriverObjectType':
        for obj in Driver_Object.objects.filter(q_filter):
            return_list.append(obj)
    elif observable_type == 'LinkObjectType':
        for obj in Link_Object.objects.filter(q_filter):
            return_list.append(obj)

    return return_list

def get_related_objects_for_object(object_id, object_type, quick=False):
    """ Return the list of related objects for a given object and type.
        The quick parameter will kind of normalize the return values so it can be used in the quick panel.
    """
    return_list = []
    try:
        related_objects_all = Related_Object.objects.filter(
            Q(object_one_id=object_id, object_one_type=object_type)|
            Q(object_two_id=object_id, object_two_type=object_type)
        )
    except Related_Object.DoesNotExist:
        return return_list
    for object_relation in related_objects_all:
        if object_relation.object_one_id == object_id:
            related_objects = get_object_for_observable(object_relation.object_two_type, object_id=object_relation.object_two_id)
        else:
            related_objects = get_object_for_observable(object_relation.object_one_type, object_id=object_relation.object_one_id)
        return_list.append({'objects': related_objects, 'relation': object_relation.relationship})
    return return_list
