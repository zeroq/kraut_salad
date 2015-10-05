# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.conf import settings

import cybox.utils
from cybox.core import Observable, Observables
from cybox.objects.file_object import File
from cybox.objects.email_message_object import EmailMessage, EmailHeader, Links, EmailRecipients, Attachments
from cybox.objects.address_object import Address, EmailAddress
from cybox.objects.link_object import Link
from cybox.objects.uri_object import URI
from cybox.objects.http_session_object import HTTPMessage, HTTPClientRequest, HTTPRequestResponse, HTTPSession, HTTPRequestHeader, HTTPRequestLine, HTTPRequestHeaderFields, HostField
from cybox.objects.port_object import Port
from cybox.objects.mutex_object import Mutex
from cybox.common import Hash, String, PositiveInteger

from kraut_parser.models import EmailMessage_Object, File_Object, Address_Object, URI_Object, HTTPSession_Object
from kraut_parser.utils import get_related_objects_for_object

### TODO: create a function for each object type to return the corresponding cybox object
def cybox_object_file(obj, meta=None):
    # TODO: missing File_Custom_Properties
    f = File()
    if obj.md5_hash != 'No MD5':
        f.add_hash(Hash(obj.md5_hash))
    if obj.sha256_hash != 'No SHA256':
        f.add_hash(Hash(obj.sha256_hash))
    if meta:
        f.file_name = meta.file_name
        f.file_extension = meta.file_extension
        f.file_path = meta.file_path
        f.size_in_bytes = meta.file_size
    return f

def cybox_object_http(obj):
    http_session = HTTPSession()
    hh = HTTPRequestResponse()
    hc = HTTPClientRequest()
    if obj.client_request.message_body:
        hm = HTTPMessage()
        hm.lenght = len(obj.client_request.message_body)
        hm.message_body = String(obj.client_request.message_body)
        hc.http_message_body = hm
    rh = HTTPRequestHeader()
    if obj.client_request.raw_header:
        rh.raw_header = String(obj.client_request.raw_header)
    hhf = HTTPRequestHeaderFields()
    hhf.user_agent = String(obj.client_request.user_agent)
    host_field = HostField()
    host_field.domain_name = URI(value=obj.client_request.domain_name)
    port = Port()
    port.port_value = PositiveInteger(obj.client_request.port.port)
    host_field.port = port
    hhf.host = host_field
    rh.parsed_header = hhf
    hc.http_request_header = rh

    hl = HTTPRequestLine()
    hl.http_method = String(obj.client_request.request_method)
    hl.version = String(obj.client_request.request_version)
    hl.value = String(obj.client_request.request_uri)
    hc.http_request_line = hl
    hh.http_client_request = hc
    http_session.http_request_response = [hh]
    return http_session

def cybox_object_address(obj):
    a = Address()
    a.address_value =obj.address_value
    a.category = obj.category
    a.condition = obj.condition
    return a

def cybox_object_uri(obj):
    u = URI()
    u.value = obj.uri_value
    u.type_ = obj.uri_type
    u.condition = obj.condition
    return u

def cybox_object_email(obj):
    e = EmailMessage()
    e.raw_body = obj.raw_body
    e.raw_header = obj.raw_header
    # Links
    e.links = Links()
    for link in obj.links.all():
        pass
    # Attachments
    e.attachments = Attachments()
    attachment_objects = []
    for att in obj.attachments.all():
        for meta in att.file_meta.all():
            fobj = cybox_object_file(att, meta)
            e.attachments.append(fobj.parent.id_)
            fobj.add_related(e, "Contained_Within", inline=False)
            attachment_objects.append(fobj)
    # construct header information
    h = EmailHeader()
    h.subject = obj.subject
    h.date = obj.email_date
    h.message_id = obj.message_id
    h.content_type = obj.content_type
    h.mime_version = obj.mime_version
    h.user_agent = obj.user_agent
    h.x_mailer = obj.x_mailer
    # From
    for from_ in obj.from_string.all():
        from_address = EmailAddress(from_.sender)
        from_address.is_spoofed = from_.is_spoofed
        from_address.condition = from_.condition
        h.from_ = from_address
    # Sender
    for sender in obj.sender.all():
        sender_address = EmailAddress(sender.sender)
        sender_address.is_spoofed = sender.is_spoofed
        sender_address.condition = sender.condition
        h.sender.add(sender_address)
    # To
    recipients = EmailRecipients()
    for recipient in obj.recipients.all():
        rec_address = EmailAddress(recipient.recipient)
        rec_address.is_spoofed = recipient.is_spoofed
        rec_address.condition = recipient.condition
        recipients.append(rec_address)
    h.to = recipients
    # CC
    recipients = EmailRecipients()
    for recipient in obj.recipients_cc.all():
        rec_address = EmailAddress(recipient.recipient)
        rec_address.is_spoofed = recipient.is_spoofed
        rec_address.condition = recipient.condition
        recipients.append(rec_address)
    h.cc = recipients
    # BCC
    recipients = EmailRecipients()
    for recipient in obj.recipients_bcc.all():
        rec_address = EmailAddress(recipient.recipient)
        rec_address.is_spoofed = recipient.is_spoofed
        rec_address.condition = recipient.condition
        recipients.append(rec_address)
    h.bcc = recipients
    e.header = h
    return e, attachment_objects

def cybox_file(observable, observable_type, objects):
    nsname, nsurl = observable.namespace.split(':', 1)
    NS = cybox.utils.Namespace(nsurl, nsname)
    cybox.utils.set_id_namespace(NS)
    observables = Observables()
    for obj in objects:
        for meta in obj.file_meta.all():
            f = cybox_object_file(obj, meta)
            # get related objects
            related_objects_list = get_related_objects_for_object(obj.id, observable_type)
            for rel_obj_dict in related_objects_list:
                for rel_obj in rel_obj_dict['objects']:
                    if isinstance(rel_obj, EmailMessage_Object):
                        rel_o, attachments_list = cybox_object_email(rel_obj)
                        f.add_related(rel_o, rel_obj_dict['relation'], True)
                        for att in attachments_list:
                            observables.add(Observable(att))
                        continue
                    elif isinstance(rel_obj, File_Object):
                        for rel_meta in rel_obj.file_meta.all():
                            rel_o = cybox_object_file(rel_obj, rel_meta)
                            f.add_related(rel_o, rel_obj_dict['relation'], True)
                        continue
                    elif isinstance(rel_obj, Address_Object):
                        rel_o = cybox_object_address(rel_obj)
                        f.add_related(rel_o, rel_obj_dict['relation'], True)
                        continue
                    elif isinstance(rel_obj, URI_Object):
                        rel_o = cybox_object_uri(rel_obj)
                        f.add_related(rel_o, rel_obj_dict['relation'], True)
                        continue
                    elif isinstance(rel_obj, HTTPSession_Object):
                        rel_o = cybox_object_http(rel_obj)
                        f.add_related(rel_o, rel_obj_dict['relation'], True)
                        continue
            o = Observable(f)
            o.title = observable.name
            o.description = observable.description
            observables.add(o)
    return observables

def cybox_address(observable, observable_type, objects):
    nsname, nsurl = observable.namespace.split(':', 1)
    NS = cybox.utils.Namespace(nsurl, nsname)
    cybox.utils.set_id_namespace(NS)
    observables = Observables()
    for obj in objects:
        a = cybox_object_address(obj)
        # get related objects
        related_objects_list = get_related_objects_for_object(obj.id, observable_type)

        o = Observable(a)
        o.title = observable.name
        o.description = observable.description
        observables.add(o)
    return observables

def cybox_uri(observable, observable_type, objects):
    nsname, nsurl = observable.namespace.split(':', 1)
    NS = cybox.utils.Namespace(nsurl, nsname)
    cybox.utils.set_id_namespace(NS)
    observables = Observables()
    for obj in objects:
        u = cybox_object_uri(obj)
        # get related objects
        related_objects_list = get_related_objects_for_object(obj.id, observable_type)

        o = Observable(u)
        o.title = observable.name
        o.description = observable.description
        observables.add(o)
    return observables

def cybox_http(observable, observable_type, objects):
    nsname, nsurl = observable.namespace.split(':', 1)
    NS = cybox.utils.Namespace(nsurl, nsname)
    cybox.utils.set_id_namespace(NS)
    observables = Observables()
    for obj in objects:
        h = cybox_object_http(obj)
        # get related objects
        related_objects_list = get_related_objects_for_object(obj.id, observable_type)

        o = Observable(h)
        o.title = observable.name
        o.description = observable.description
        observables.add(o)
    return observables

def cybox_mutex(observable, observable_type, objects):
    nsname, nsurl = observable.namespace.split(':', 1)
    NS = cybox.utils.Namespace(nsurl, nsname)
    cybox.utils.set_id_namespace(NS)
    observables = Observables()
    for obj in objects:
        m = Mutex()
        m.name = obj.mutex_name
        o = Observable(m)
        o.title = observable.name
        o.description = observable.description
        observables.add(o)
    return observables
