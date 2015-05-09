# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.conf import settings

import cybox.utils
from cybox.core import Observable, Observables
from cybox.objects.file_object import File
from cybox.objects.email_message_object import EmailMessage
from cybox.common import Hash

from kraut_parser.models import EmailMessage_Object
from kraut_parser.utils import get_related_objects_for_object

### TODO: create a function for each object type to return the corresponding cybox object
def cybox_object_file(obj):
    f = File()
    return f

def cybox_object_email(obj):
    e = EmailMessage()
    e.raw_body = obj.raw_body
    e.raw_header = obj.raw_header
    return e

def cybox_file(observable, observable_type, objects):
    # TODO: get the correct namespace information
    NS = cybox.utils.Namespace(settings.MY_NAMESPACE.keys()[0], observable.namespace)
    cybox.utils.set_id_namespace(NS)
    observables = Observables()
    for obj in objects:
        for meta in obj.file_meta.all():
            f = File()
            if obj.md5_hash != 'No MD5':
                f.add_hash(Hash(obj.md5_hash))
            if obj.sha256_hash != 'No SHA256':
                f.add_hash(Hash(obj.sha256_hash))
            f.file_name = meta.file_name
            f.file_extension = meta.file_extension
            f.file_path = meta.file_path
            f.size_in_bytes = meta.file_size
            # get related objects
            related_objects_list = get_related_objects_for_object(obj.id, observable_type)
            for rel_obj_dict in related_objects_list:
                for rel_obj in rel_obj_dict['objects']:
                    if isinstance(rel_obj, EmailMessage_Object):
                        rel_o = cybox_object_email(rel_obj)
                    elif isinstance(rel_obj, File_Object):
                        rel_o = cybox_object_file(rel_obj)
                    f.add_related(rel_o, rel_obj_dict['relation'], True)
            o = Observable(f)
            o.title = observable.name
            o.description = observable.description
            observables.add(o)
    return observables
