#!/usr/bin/env python
# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.conf import settings
import dateutil
import libtaxii as t
import libtaxii.clients as tc
from libtaxii.common import generate_message_id, gen_filename
from libtaxii.messages_11 import CollectionInformationRequest, PollRequest, MSG_POLL_RESPONSE
from libtaxii.constants import *
from dateutil.tz import tzutc
from urlparse import urlparse
import os, datetime

class CollectionRequest:

    def __init__(self, url):
        self.url = urlparse(url)

    def run(self):
        client = tc.HttpClient()
        # TODO: handle authentication stuff
        #client.set_auth_type(tc.AUTH_NONE)
        client.set_use_https(False)

        r = CollectionInformationRequest(generate_message_id())
        col_xml = r.to_xml(pretty_print=True)

        if ':' in self.url.netloc:
            host = self.url.netloc.split(':')[0]
            server_port = self.url.netloc.split(':')[1]
        else:
            host = self.url.netloc
            server_port = None
        if server_port:
            http_resp = client.call_taxii_service2(host, self.url.path, VID_TAXII_XML_11, col_xml, port = server_port)
        else:
            http_resp = client.call_taxii_service2(host, self.url.path, VID_TAXII_XML_11, col_xml)
        taxii_message = t.get_message_from_http_response(http_resp, r.message_id)
        return taxii_message.to_dict()

class CollectionPoll:

    def __init__(self, url, collection_name, begin_timestamp=None, taxii_version=VID_TAXII_XML_11):
        self.url = urlparse(url)
        if ':' in self.url.netloc:
            self.host = self.url.netloc.split(':')[0]
            self.port = self.url.netloc.split(':')[1]
        else:
            self.host = self.url.netloc
            self.port = None
        self.collection_name = collection_name
        self.begin_timestamp = begin_timestamp
        self.taxii_version = taxii_version

    def handle_response(self, response):
        """ store response in import directory """
        if response.message_type == MSG_POLL_RESPONSE:
            if response.more:
                # TODO: handle More=True in response
                print("TODO: handle More=True!!!")
            self.write_response_to_import(response, settings.MY_IMPORT_DIRECTORY)

    def write_response_to_import(self, response, dest_dir):
        """ write response to disc """
        if not os.path.exists(dest_dir):
            os.makedirs(dest_dir)

        for cb in response.content_blocks:
            if cb.content_binding.binding_id == CB_STIX_XML_10: sformat = '_STIX10_'
            elif cb.content_binding.binding_id == CB_STIX_XML_101: sformat = '_STIX101_'
            elif cb.content_binding.binding_id == CB_STIX_XML_11: sformat = '_STIX11_'
            elif cb.content_binding.binding_id == CB_STIX_XML_111: sformat = '_STIX111_'
            else: sformat = ''
            ext = '.xml'

            date_string = 's' + datetime.datetime.now().isoformat()
            if cb.timestamp_label: date_string = 't' + cb.timestamp_label.isoformat()

            filename = gen_filename(response.collection_name, sformat, date_string, ext)
            filename = os.path.join(dest_dir, filename)
            with open(filename, 'w') as f:
                f.write(cb.content)
        return True

    def create_client(self):
        """ create client for connection """
        client = tc.HttpClient()
        client.set_use_https(False)
        # TODO: add authentication stuff
        return client

    def create_request_message(self):
        if self.begin_timestamp:
            begin_ts = dateutil.parser.parse(self.begin_timestamp)
        # TODO: add support for end timestamp
        end_ts = None
        create_kwargs = {
            'message_id': generate_message_id(),
            'collection_name': self.collection_name,
            'exclusive_begin_timestamp_label': begin_ts,
            'inclusive_end_timestamp_label': end_ts
        }
        create_kwargs['poll_parameters'] = PollRequest.PollParameters()
        poll_req = PollRequest(**create_kwargs)
        return poll_req

    def run(self):
        request_message = self.create_request_message()
        client = self.create_client()

        if self.port:
            resp = client.call_taxii_service2(self.host, self.url.path, self.taxii_version, request_message.to_xml(pretty_print=True), self.port)
        else:
            resp = client.call_taxii_service2(self.host, self.url.path, self.taxii_version, request_message.to_xml(pretty_print=True))
        r = t.get_message_from_http_response(resp, '0')
        self.handle_response(r)


#def main():
#    """ Send a Feed Information Request to a Taxii 1.1 Server """
#    script = CollectionRequest(url='http://hailataxii.com/taxii-discovery-service/')
#    res = script.run()
#    print res

#def main2():
#    script = CollectionPoll(url='http://hailataxii.com/taxii-discovery-service/', collection_name='guest.Abuse_ch', begin_timestamp='2015-12-20T13:13:48.751691+0000')
#    script.run()

#if __name__ == "__main__":
#    main2()
