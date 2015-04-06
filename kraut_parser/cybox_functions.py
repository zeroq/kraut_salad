# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

import dateutil, pytz

from kraut_parser.models import URI_Object, Port_Object

def handle_email_object(email_obj):
    """extract all relevant information from a cybox email object
    @email_obj: cybox email object in json format
    returns: dictionary with email object information
    """
    email_dict = {
        'raw_body': 'No Raw Body',
        'raw_header': 'No Raw Header',
        'subject': 'No Subject',
        'email_date': None,
        'message_id': 'No Message ID',
        'content_type': 'No Content Type',
        'mime_version': 'No Mime Version',
        'user_agent': 'No User Agent',
        'x_mailer': 'No X-Mailer',
        'attachments': [],
        'from': None,
        'to': []
    }
    if 'attachments' in email_obj and isinstance(email_obj['attachments'], list):
        for item in email_obj['attachments']:
            if 'object_reference' in item:
                email_dict['attachments'].append(item['object_reference'])
    if 'raw_body' in email_obj:
        email_dict['raw_body'] = email_obj['raw_body']
    if 'raw_header' in email_obj:
        email_dict['raw_header'] = email_obj['raw_header']
    if 'header' in email_obj:
        if 'subject' in email_obj['header']:
            if isinstance(email_obj['header']['subject'], dict):
                email_dict['subject'] = email_obj['header']['subject'].get('value', 'No Subject')
            else:
                email_dict['subject'] = email_obj['header']['subject']
        if 'message_id' in email_obj['header']:
            if isinstance(email_obj['header']['message_id'], dict):
                email_dict['message_id'] = email_obj['header']['message_id'].get('value', 'No Message ID')
            else:
                email_dict['message_id'] = email_obj['header']['message_id']
        if 'content_type' in email_obj['header']:
            if isinstance(email_obj['header']['content_type'], dict):
                email_dict['content_type'] = email_obj['header']['content_type'].get('value', 'No Content Type')
            else:
                email_dict['content_type'] = email_obj['header']['content_type']
        if 'date' in email_obj['header']:
            datetime_object = dateutil.parser.parse(email_obj['header']['date'])
            # add UTC timezone if timezone information is missing
            if not datetime_object.tzinfo:
                datetime_object = datetime_object.replace(tzinfo=pytz.utc)
            email_dict['email_date'] = datetime_object
        if 'mime_version' in email_obj['header']:
            if isinstance(email_obj['header']['mime_version'], dict):
                email_dict['mime_version'] = email_obj['header']['mime_version'].get('value', 'No Mime Version')
            else:
                email_dict['mime_version'] = email_obj['header']['mime_version']
        if 'x_mailer' in email_obj['header']:
            if isinstance(email_obj['header']['x_mailer'], dict):
                email_dict['x_mailer'] = email_obj['header']['x_mailer'].get('value', 'No X-Mailer')
            else:
                email_dict['x_mailer'] = email_obj['header']['x_mailer']
        if 'user_agent' in email_obj['header']:
            if isinstance(email_obj['header']['user_agent'], dict):
                email_dict['user_agent'] = email_obj['header']['user_agent'].get('value', 'No User Agent')
            else:
                email_dict['user_agent'] = email_obj['header']['user_agent']
        if 'from' in email_obj['header'] and 'address_value' in email_obj['header']['from']:
            email_from_dict = {
                'sender': 'No Sender',
                'is_spoofed': False,
                'condition': 'equals'
            }
            if isinstance(email_obj['header']['from']['address_value'], dict):
                from_string = email_obj['header']['from']['address_value'].get('value', None)
                if from_string:
                    email_from_dict['sender'] = from_string
                    email_from_dict['condition'] = email_obj['header']['from']['address_value'].get('condition', 'equals').lower()
                    email_from_dict['is_spoofed'] = email_obj['header']['from']['address_value'].get('is_spoofed', False)
            else:
                email_from_dict['sender'] = email_obj['header']['from']['address_value']
            email_dict['from'] = email_from_dict
        if 'to' in email_obj['header'] and isinstance(email_obj['header']['to'], list):
            for item in email_obj['header']['to']:
                if 'address_value' in item:
                    email_rec_dict = {
                        'recipient': 'No recipient',
                        'is_spoofed': False,
                        'condition': 'equals'
                    }
                    if isinstance(item['address_value'], dict):
                        recipient_string = item['address_value'].get('value', None)
                        if recipient_string:
                            email_rec_dict['recipient'] = recipient_string
                            email_rec_dict['condition'] = item['address_value'].get('condition', 'equals').lower()
                            email_rec_dict['is_spoofed'] = item['address_value'].get('is_spoofed', False)
                    else:
                        email_rec_dict['recipient'] = item['address_value']
                    email_dict['to'].append(email_rec_dict)
    return email_dict

def handle_file_object(file_obj):
    """extract all relevant information from a cybox file object
    @file_obj: cybox file object in json format
    returns: dictionary with file object information
    """
    file_custom_properties_lst = []
    file_meta_dict = {
        'file_name': 'No Name',
        'file_extension': 'No Extension',
        'file_path': 'No Path',
        'file_size': 0
    }
    file_dict = {
        'md5_hash': 'No MD5',
        'sha256_hash': 'No SHA256'
    }
    # extract custom properties
    if 'custom_properties' in file_obj:
        for prop in file_obj['custom_properties']:
            property_dict = {
                'property_name': prop['name'],
                'property_value': prop['value']
            }
            file_custom_properties_lst.append(property_dict)
    # extract meta information
    if 'file_name' in file_obj:
        if isinstance(file_obj['file_name'], dict):
            file_meta_dict['file_name'] = file_obj['file_name'].get('value', 'No Name')
        else:
            file_meta_dict['file_name'] = file_obj['file_name']
    if 'file_path' in file_obj:
        if isinstance(file_obj['file_path'], dict):
            file_meta_dict['file_path'] = file_obj['file_path'].get('value', 'No Path')
        else:
            file_meta_dict['file_path'] = file_obj['file_path']
    if 'file_extension' in file_obj:
        if file_obj['file_extension'].startswith('.'):
            file_meta_dict['file_extension'] = file_obj['file_extension'][1:]
        else:
            file_meta_dict['file_extension'] = file_obj['file_extension']
    if 'size_in_bytes' in file_obj:
        if isinstance(file_obj['size_in_bytes'], dict):
            size_value = file_obj['size_in_bytes'].get('value', 0)
            if isinstance(size_value, (tuple, list, dict, set)):
                # ignore size in between items, too unspecific
                pass
            else:
                file_meta_dict['file_size'] = size_value
        else:
            file_meta_dict['file_size'] = int(file_obj['size_in_bytes'])
    # extract MD5 and SHA256 from Object
    if 'hashes' in file_obj:
        for hash_dict in file_obj['hashes']:
            if isinstance(hash_dict['type'], dict):
                if hash_dict['type']['value'] == 'MD5':
                    if 'value' in hash_dict['simple_hash_value']:
                        file_dict['md5_hash'] = hash_dict['simple_hash_value']['value'].lower()
                    else:
                        file_dict['md5_hash'] = hash_dict['simple_hash_value'].lower()
                elif hash_dict['type']['value'] == 'SHA256':
                    if 'value' in hash_dict['simple_hash_value']:
                        file_dict['sha256_hash'] = hash_dict['simple_hash_value']['value'].lower()
                    else:
                        file_dict['sha256_hash'] = hash_dict['simple_hash_value'].lower()
            else:
                if hash_dict['type'] == 'MD5':
                    if 'value' in hash_dict['simple_hash_value']:
                        file_dict['md5_hash'] = hash_dict['simple_hash_value']['value'].lower()
                    else:
                        file_dict['md5_hash'] = hash_dict['simple_hash_value'].lower()
                elif hash_dict['type'] == 'SHA256':
                    if 'value' in hash_dict['simple_hash_value']:
                        file_dict['sha256_hash'] = hash_dict['simple_hash_value']['value'].lower()
                    else:
                        file_dict['sha256_hash'] = hash_dict['simple_hash_value'].lower()
    return file_dict, file_meta_dict, file_custom_properties_lst

def handle_uri_object(uri_obj):
    """extract all relevant information from a cybox uri object
    @uri_obj: cybox uri object in json format
    returns: dictionary with uri object information
    """
    uri_dict = {
        'uri_value': 'No Value',
        'uri_type': 'No Type',
        'condition': 'equals'
    }
    uri_dict['uri_type'] = uri_obj.get('type', 'Domain Name')
    if 'value' in uri_obj and isinstance(uri_obj['value'], (tuple, list, dict, set)):
        uri_dict['uri_value'] = uri_obj['value'].get('value', 'No Value')
        uri_dict['condition'] = uri_obj['value'].get('condition', 'equals').lower()
    else:
        uri_dict['uri_value'] = uri_obj.get('value', 'No Value')
        uri_dict['condition'] = 'equals'
    return uri_dict

def handle_address_object(adr_obj):
    """extract all relevant information from a cybox address object
    @adr_obj: cybox address object in json format
    returns: a list of dictionaries containing address object information
    """
    address_list = []
    if 'address_value' in adr_obj and isinstance(adr_obj['address_value'], (tuple, list, dict, set)):
        address_value = adr_obj['address_value'].get('value', 'NotSet')
        if isinstance(address_value, (tuple, list, dict, set)):
            for item in address_value:
                adr_dict = {
                    'address_value': 'No Address',
                    'category': 'ipv4-addr',
                    'condition': 'equals'
                }
                adr_dict['address_value'] = item
                adr_dict['category'] = adr_obj.get('category', 'ipv4-addr')
                adr_dict['condition'] = adr_obj['address_value'].get('condition', 'equals').lower()
                address_list.append(adr_dict)
            return address_list
        else:
            adr_dict = {
                'address_value': 'No Address',
                'category': 'ipv4-addr',
                'condition': 'equals'
            }
            adr_dict['address_value'] = adr_obj['address_value'].get('value', 'No Address')
            adr_dict['category'] = adr_obj.get('category', 'ipv4-addr')
            adr_dict['condition'] = adr_obj['address_value'].get('condition', 'equals').lower()
            return [adr_dict]
    else:
        adr_dict = {
            'address_value': 'No Address',
            'category': 'ipv4-addr',
            'condition': 'equals'
        }
        adr_dict['address_value'] = adr_obj['address_value']
        adr_dict['category'] = adr_obj.get('category', 'ipv4-addr')
        adr_dict['condition'] = 'equals'
        return [adr_dict]
    return []

def handle_mutex_object(mu_obj):
    """extract all relevant information from a cybox mutex object
    @mu_obj: cybox mutex object in json format
    returns: a dictionary containing mutex object information
    """
    mutex_dict = {
        'mutex_name': 'No Mutex',
        'condition': 'equals'
    }
    if 'name' in mu_obj and isinstance(mu_obj['name'], (tuple, list, dict, set)):
        mutex_dict['mutex_name'] = mu_obj['name'].get('value', 'No Mutex')
        mutex_dict['condition'] = mu_obj['name'].get('condition', 'equals').lower()
    else:
        mutex_dict['mutex_name'] = mu_obj['name']
        mutex_dict['condition'] = 'equals'
    return mutex_dict

def handle_code_object(co_obj):
    """extract all relevant information from a cybox code object
    @co_obj: cybox code object in json format
    returns: a list of dictionaries containing code object information
    """
    code_list = []
    if 'custom_properties' in co_obj:
        for custom_property in co_obj['custom_properties']:
            code_dict = {
                'custom_value': 'No Value',
                'custom_condition': 'equals',
                'purpose': 'No Purpose',
                'code_language': 'No Language',
                'code_segment': 'No Segment'
            }
            code_dict['custom_value'] = custom_property.get('value', 'No Value')
            code_dict['custom_condition'] = custom_property.get('condition', 'equals').lower()
            code_dict['code_segment'] = co_obj.get('code_segment', 'No Segment')
            code_dict['code_language'] = co_obj.get('code_language', 'No Language')
            code_dict['purpose'] = co_obj.get('purpose', 'No Purpose')
            code_list.append(code_dict)
    return code_list

def handle_driver_object(dr_obj):
    """extract all relevant information from a cybox driver object
    @co_obj: cybox driver object in json format
    returns: a dictionaries containing driver object information
    """
    driver_dict = {
        'driver_name': 'No Name',
        'condition': 'equals'
    }
    if 'driver_name' in dr_obj:
        driver_dict['driver_name'] = dr_obj['driver_name'].get('value', 'No Name')
        driver_dict['condition'] = dr_obj['driver_name'].get('condition', 'equals').lower()
    return driver_dict

def handle_link_object(li_obj):
    """extract all relevant information from a cybox link object
    @co_obj: cybox link object in json format
    returns: a dictionaries containing link object information
    """
    link_dict = {
        'link': 'No Link',
        'link_type': 'No Type',
        'url_label': 'No Label',
        'condition': 'equals'
    }
    if 'value' in li_obj:
        if isinstance(li_obj['value'], dict):
            link_dict['link'] = li_obj['value'].get('value', 'No Link')
            link_dict['condition'] = li_obj['value'].get('condition', 'equals').lower()
    if 'url_label' in li_obj:
        if isinstance(li_obj['url_label'], dict):
            link_dict['url_label'] = li_obj['url_label'].get('value', 'No Label')
    if 'type' in li_obj:
        link_dict['link_type'] = li_obj.get('type', 'No Type')
    return link_dict

def handle_http_session_object(http_obj):
    """extract relevant information from a cybox http session object
    @http_obj: cybox http session object in json format
    returns: list of dictionaries
    """
    client_dict_list = []
    if 'http_request_response' in http_obj:
        for request in http_obj['http_request_response']:
            client_dict = {
                'raw_header': None,
                'message_body': None,
                'request_method': 'GET',
                'request_uri': '/',
                'request_version': '1.1',
                'user_agent': None,
                'domain_name': None,
                'port': None,
            }
            # get message body
            if 'http_client_request' in request and 'http_message_body' in request['http_client_request']:
                client_dict['message_body'] = request['http_client_request']['http_message_body'].get('message_body', None)
            # get raw header
            if 'http_client_request' in request and 'http_request_header' in request['http_client_request']:
                client_dict['raw_header'] = request['http_client_request']['http_request_header'].get('raw_header', None)
                # get host information
                if 'parsed_header' in request['http_client_request']['http_request_header']:
                    host = request['http_client_request']['http_request_header']['parsed_header'].get('host', None)
                    if host:
                        if 'domain_name' in host:
                            uri_dict = {
                                'uri_value': host['domain_name'].get('value', 'No Value'),
                                'uri_type': 'Domain Name',
                                'condition': 'equals'
                            }
                            uri_object, uri_object_created = URI_Object.objects.get_or_create(**uri_dict)
                            client_dict['domain_name'] = uri_object
                        if 'port' in host:
                            port_dict = {
                                'port': host['port'].get('port_value', 'No Value')
                            }
                            port_object, port_object_created = Port_Object.objects.get_or_create(**port_dict)
                            client_dict['port'] = port_object
                    # get user agent information
                    client_dict['user_agent'] = request['http_client_request']['http_request_header']['parsed_header'].get('user_agent', None)
            if 'http_client_request' in request and 'http_request_line' in request['http_client_request']:
                client_dict['request_method'] = request['http_client_request']['http_request_line'].get('http_method', 'GET')
                client_dict['request_uri'] = request['http_client_request']['http_request_line'].get('value', '/')
                client_dict['request_version'] = request['http_client_request']['http_request_line'].get('version', '1.1')
            client_dict_list.append(client_dict)
    return client_dict_list

def handle_win_registry_object(re_obj):
    """extract all relevant information from a cybox windows registry object
    @co_obj: cybox windows registry object in json format
    returns: a dictionaries containing windows registry object information
    """
    reg_list = []
    if 'values' in re_obj:
        for item in re_obj['values']:
            reg_dict = {
                'key': 'No Key',
                'hive': 'No Hive',
                'data': 'No Data',
                'data_name': ' No Data Name'
            }
            if 'data' in item:
                if isinstance(item['data'], dict):
                    reg_dict['data'] = item['data'].get('value', 'No Data')
                else:
                    reg_dict['data'] = item['data']
            if 'name' in item:
                if isinstance(item['name'], dict):
                    reg_dict['data_name'] = item['name'].get('value', 'No Data Name')
                else:
                    reg_dict['data_name'] = item['name']
            if 'hive' in re_obj:
                if isinstance(re_obj['hive'], dict):
                    reg_dict['hive'] = re_obj['hive'].get('value', 'No Hive')
            if 'key' in re_obj:
                if isinstance(re_obj['key'], dict):
                    reg_dict['key'] = re_obj['key'].get('value', 'No Key')
            reg_list.append(reg_dict)
    else:
        reg_dict = {
            'key': 'No Key',
            'hive': 'No Hive',
            'data': 'No Data',
            'data_name': ' No Data Name'
        }
        if 'key' in re_obj:
            if isinstance(re_obj['key'], dict):
                reg_dict['key'] = re_obj['key'].get('value', 'No Key')
        if 'hive' in re_obj:
            if isinstance(re_obj['hive'], dict):
                reg_dict['hive'] = re_obj['hive'].get('value', 'No Hive')
        reg_list.append(reg_dict)
    return reg_list


