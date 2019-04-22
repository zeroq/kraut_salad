# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

import sys, json, re, pytz, os, time, shutil
from dateutil.parser import parse as date_parser
from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from stix.utils.parser import EntityParser
# import database models
from kraut_parser.models import Observable, Indicator, Indicator_Type, Confidence, ThreatActor, TA_Alias, TA_Roles, TA_Types, Package, Package_Intent, Package_Reference, ObservableComposition
from kraut_parser.models import Related_Object, File_Object, File_Meta_Object, File_Custom_Properties, URI_Object, Address_Object, Mutex_Object, Code_Object, Driver_Object, Link_Object, Win_Registry_Object, EmailMessage_Object, EmailMessage_from, EmailMessage_recipient, HTTPSession_Object, HTTPClientRequest, DNSQuery_Object, DNSQuestion
from kraut_parser.models import TTP, RelatedTTP, MalwareInstance, MalwareInstanceNames, MalwareInstanceTypes, AttackPattern
from kraut_parser.models import Campaign, RelationCampaignTTP
from kraut_parser.models import Namespace, Indicator_Kill_Chain_Phase
from kraut_parser.models import WindowsExecutable_Object, PEImports, ImportedFunction, PEExports, ExportedFunction, PESections
# import helper functions
from kraut_parser.cybox_functions import handle_file_object, handle_uri_object, handle_address_object, handle_mutex_object, handle_code_object, handle_driver_object, handle_link_object, handle_win_registry_object, handle_email_object, handle_http_session_object, handle_dns_query_object
from kraut_parser.cybox_functions import handle_windows_executable_object

class Command(BaseCommand):
    args = '<stix_xml>'
    help = 'parses given STIX xml documents and writes results to the database'

    def __init__(self, *args, **kwargs):
        """init function that initializes some class-wide dictionaries to track references and missing objects
        """
        super(Command, self).__init__(*args, **kwargs)
        self.supported_stix_versions = set(['1.0.1', '1.1.1', '1.0', '1.1'])
        self.stix_namespaces_dict = {}
        self.common_elements = (
            'description',
            'id',
            'version',
            'major_version',
            'update_version',
            'minor_version',
            'title',
            'short_description'
        )
        self.missed_objects = {}
        self.missed_elements = {
            'campaign': {},
            'threat_actor': {},
            'indicator': {},
            'observable': {},
            'stix': {},
            'ttps': {}
        }
        self.id_mapping = {
            'observables': {},
            'objects': {},
            'indicators': {},
            'threat_actors': {},
            'campaigns': {},
            'ttps': {},
            'compositions': {}
        }
        self.missing_references = {
            'actor_2_actor': {},
            'actor_2_campaign': {},
            'actor_2_ttp': {},
            'indicator_2_indicator': {},
            'indicator_2_observable': {},
            'object_2_object': {},
            'email_2_attachment': {},
            'composite_2_observable': {},
            'ttp_2_ttp': {},
            'campaign_2_ttp': {},
            'indicator_2_ttp': {},
        }

    def __check_version(self, version):
        """check stix xml version against supported list
        @version: stix xml version found in given xml file
        returns: boolean
        """
        if version not in self.supported_stix_versions:
            return False
        return True

    def perform_version_check(self, stix_json):
        """check if version entry exists and check if the value is supported
        @stix_json: json representation of a stix report
        returns: boolean
        """
        self.stdout.write('--> performing version check ... ', ending='')
        sys.stdout.flush()
        if 'version' in stix_json:
            if not self.__check_version(stix_json['version']):
                self.stdout.write('found %s ... [FAIL]' % (stix_json['version']))
                return False
        else:
            self.stdout.write('not found ... [FAIL]')
            return False
        self.stdout.write('found %s ... [DONE]' % (stix_json['version']))
        return True

    def get_database_object(self, object_id, object_type):
        """get the corresponding database entry for the given object id and type
        @object_id: id of the database entry to retrieve
        @object_type: type of the object that we want to retrieve
        returns: database object of the requested type and id
        """
        db_object = None
        if object_type == 'FileObjectType':
            db_object = File_Object.objects.get(id=object_id)
        elif object_type == 'URIObjectType' or object_type == 'DomainNameObjectType':
            db_object = URI_Object.objects.get(id=object_id)
        elif object_type == 'AddressObjectType':
            db_object = Address_Object.objects.get(id=object_id)
        elif object_type == 'MutexObjectType':
            db_object = Mutex_Object.objects.get(id=object_id)
        elif object_type == 'CodeObjectType':
            db_object = Code_Object.objects.get(id=object_id)
        elif object_type == 'WindowsDriverObjectType':
            db_object = Driver_Object.objects.get(id=object_id)
        elif object_type == 'LinkObjectType':
            db_object = Link_Object.objects.get(id=object_id)
        elif object_type == 'WindowsRegistryKeyObjectType':
            db_object = Win_Registry_Object.objects.get(id=object_id)
        elif object_type == 'EmailMessageObjectType':
            db_object = EmailMessage_Object.objects.get(id=object_id)
        elif object_type == 'HTTPSessionObjectType':
            db_object = HTTPSession_Object.objects.get(id=object_id)
        elif object_type == 'DNSQueryObjectType':
            db_object = DNSQuery_Object.objects.get(id=object_id)
        elif object_type == 'WindowsExecutableFileObjectType':
            db_object = WindowsExecutable_Object.objects.get(id=object_id)
        else:
            print('No DB Object found?!')
        return db_object

    def determine_create_object(self, observable_object, object_type, object_data, object_id):
        """get or create sitx database object based on given type and information
        @observable_object: database object of the observable the object belongs to
        @object_type: type of the object that we want to create
        @object_data: stix object data in json format
        @object_id: xml indentifier of the given object
        returns: list of database objects
        """
        object_list = []
        if object_type == 'FileObjectType':
            # create file object
            file_dict, file_meta_dict, file_custom_properties_lst = handle_file_object(object_data)
            # create meta information object
            file_meta_object, file_meta_created = File_Meta_Object.objects.get_or_create(**file_meta_dict)
            # items that have a hash should be checked for existance
            if file_dict['md5_hash'] != 'No MD5' or file_dict['sha256_hash'] != 'No SHA256':
                file_object, file_created = File_Object.objects.get_or_create(**file_dict)
            else:
                try:
                    file_object = File_Object.objects.get(
                        md5_hash=file_dict['md5_hash'],
                        sha256_hash=file_dict['sha256_hash'],
                        file_meta=file_meta_object,
                        observables=observable_object)
                except File_Object.DoesNotExist:
                    file_object = File_Object(**file_dict)
                    file_object.save()
                file_created = False
            # add meta information to file object
            file_object.file_meta.add(file_meta_object)
            # create custom properties
            for custom_dict in file_custom_properties_lst:
                file_custom_object, file_custom_created = File_Custom_Properties.objects.get_or_create(**custom_dict)
                file_object.file_custom.add(file_custom_object)
            file_object.save()
            # add observable
            file_object.observables.add(observable_object)
            file_object.save()
            # create object ID mapping
            if object_id in self.id_mapping['objects']:
                self.id_mapping['objects'][object_id].append({'object_id': file_object.id, 'object_type': object_type})
            else:
                self.id_mapping['objects'][object_id] = [{'object_id': file_object.id, 'object_type': object_type}]
            object_list.append(file_object)
        elif object_type == 'URIObjectType' or object_type == 'DomainNameObjectType':
            # create uri object
            uri_dict = handle_uri_object(object_data)
            uri_object, uri_object_created = URI_Object.objects.get_or_create(**uri_dict)
            # add observable
            uri_object.observables.add(observable_object)
            uri_object.save()
            # create object ID mapping
            if object_id in self.id_mapping['objects']:
                self.id_mapping['objects'][object_id].append({'object_id': uri_object.id, 'object_type': object_type})
            else:
                self.id_mapping['objects'][object_id] = [{'object_id': uri_object.id, 'object_type': object_type}]
            object_list.append(uri_object)
        elif object_type == 'AddressObjectType':
            # create address object
            address_dict_list = handle_address_object(object_data)
            for address_dict in address_dict_list:
                address_object, address_object_created = Address_Object.objects.get_or_create(**address_dict)
                # add observable
                address_object.observables.add(observable_object)
                address_object.save()
                # create object ID mapping
                if object_id in self.id_mapping['objects']:
                    self.id_mapping['objects'][object_id].append({'object_id': address_object.id, 'object_type': object_type})
                else:
                    self.id_mapping['objects'][object_id] = [{'object_id': address_object.id, 'object_type': object_type}]
                object_list.append(address_object)
        elif object_type == 'MutexObjectType':
            # create mutex object
            mutex_dict = handle_mutex_object(object_data)
            mutex_object, mutex_object_created = Mutex_Object.objects.get_or_create(**mutex_dict)
            # add observable
            mutex_object.observables.add(observable_object)
            mutex_object.save()
            # create object ID mapping
            if object_id in self.id_mapping['objects']:
                self.id_mapping['objects'][object_id].append({'object_id': mutex_object.id, 'object_type': object_type})
            else:
                self.id_mapping['objects'][object_id] = [{'object_id': mutex_object.id, 'object_type': object_type}]
            object_list.append(mutex_object)
        elif object_type == 'CodeObjectType':
            # create code object
            code_dict_list = handle_code_object(object_data)
            for code_dict in code_dict_list:
                code_object, code_object_created = Code_Object.objects.get_or_create(**code_dict)
                # add observable
                code_object.observables.add(observable_object)
                code_object.save()
                # create object ID mapping
                if object_id in self.id_mapping['objects']:
                    self.id_mapping['objects'][object_id].append({'object_id': code_object.id, 'object_type': object_type})
                else:
                    self.id_mapping['objects'][object_id] = [{'object_id': code_object.id, 'object_type': object_type}]
                object_list.append(code_object)
        elif object_type == 'WindowsDriverObjectType':
            # create driver object
            driver_dict = handle_driver_object(object_data)
            driver_object, driver_created = Driver_Object.objects.get_or_create(**driver_dict)
            # add observable
            driver_object.observables.add(observable_object)
            driver_object.save()
            # create object ID mapping
            if object_id in self.id_mapping['objects']:
                self.id_mapping['objects'][object_id].append({'object_id': driver_object.id, 'object_type': object_type})
            else:
                self.id_mapping['objects'][object_id] = [{'object_id': driver_object.id, 'object_type': object_type}]
            object_list.append(driver_object)
        elif object_type == 'LinkObjectType':
            # create driver object
            link_dict = handle_link_object(object_data)
            link_object, link_created = Link_Object.objects.get_or_create(**link_dict)
            # add observable
            link_object.observables.add(observable_object)
            link_object.save()
            # create object ID mapping
            if object_id in self.id_mapping['objects']:
                self.id_mapping['objects'][object_id].append({'object_id': link_object.id, 'object_type': object_type})
            else:
                self.id_mapping['objects'][object_id] = [{'object_id': link_object.id, 'object_type': object_type}]
            object_list.append(link_object)
        elif object_type == 'WindowsRegistryKeyObjectType':
            # create registry object
            reg_dict_list = handle_win_registry_object(object_data)
            for reg_dict in reg_dict_list:
                reg_object, reg_object_created = Win_Registry_Object.objects.get_or_create(**reg_dict)
                # add observable
                reg_object.observables.add(observable_object)
                reg_object.save()
                # create object ID mapping
                if object_id in self.id_mapping['objects']:
                    self.id_mapping['objects'][object_id].append({'object_id': reg_object.id, 'object_type': object_type})
                else:
                    self.id_mapping['objects'][object_id] = [{'object_id': reg_object.id, 'object_type': object_type}]
                object_list.append(reg_object)
        elif object_type == 'EmailMessageObjectType':
            # get email dictionary
            email_dict = handle_email_object(object_data)
            # get attachments
            email_attachment_list = email_dict.pop('attachments')
            # get from
            email_from_dict = email_dict.pop('from')
            # get to
            email_to_list = email_dict.pop('to')
            # create email object
            email_object, email_created = EmailMessage_Object.objects.get_or_create(**email_dict)
            # add observable
            email_object.observables.add(observable_object)
            # add from
            if email_from_dict:
                email_from_object, email_from_created = EmailMessage_from.objects.get_or_create(**email_from_dict)
                email_object.from_string.add(email_from_object)
            # add to
            if len(email_to_list)>0:
                for email_to_dict in email_to_list:
                    email_to_object, email_to_created = EmailMessage_recipient.objects.get_or_create(**email_to_dict)
                    email_object.recipients.add(email_to_object)
            # add attachments
            if len(email_attachment_list)>0:
                for attachments_reference in email_attachment_list:
                    if attachments_reference in self.id_mapping['objects']:
                        attachment_object_meta_list = self.id_mapping['objects'][attachments_reference]
                        for attachment_object_meta in attachment_object_meta_list:
                            attachment_object = self.get_database_object(attachment_object_meta['object_id'], attachment_object_meta['object_type'])
                            email_object.attachments.add(attachment_object)
                    else:
                        if object_id in self.missing_references['email_2_attachment']:
                            self.missing_references['email_2_attachment'][object_id].append({'idref': attachments_reference})
                        else:
                            self.missing_references['email_2_attachment'][object_id] = [{'idref': attachments_reference}]
            email_object.save()
            # create object ID mapping
            if object_id in self.id_mapping['objects']:
                self.id_mapping['objects'][object_id].append({'object_id': email_object.id, 'object_type': object_type})
            else:
                self.id_mapping['objects'][object_id] = [{'object_id': email_object.id, 'object_type': object_type}]
            object_list.append(email_object)
        elif object_type == 'HTTPSessionObjectType':
            # get http session dictionary
            http_dict_list = handle_http_session_object(object_data)
            for http_dict in http_dict_list:
                # create http client request object
                client_request_object, client_request_object_created = HTTPClientRequest.objects.get_or_create(**http_dict)
                # create http session object
                session_object, session_object_created = HTTPSession_Object.objects.get_or_create(client_request=client_request_object)
                # add observable
                session_object.observables.add(observable_object)
                session_object.save()
                # create object ID mapping
                if object_id in self.id_mapping['objects']:
                    self.id_mapping['objects'][object_id].append({'object_id': session_object.id, 'object_type': object_type})
                else:
                    self.id_mapping['objects'][object_id] = [{'object_id': session_object.id, 'object_type': object_type}]
                object_list.append(session_object)
        elif object_type == 'DNSQueryObjectType':
            dns_question_dict = handle_dns_query_object(object_data)
            # create dns question object
            dns_question_object, dns_question_object_created = DNSQuestion.objects.get_or_create(**dns_question_dict)
            # create dns query object
            dns_query_object, dns_query_object_created = DNSQuery_Object.objects.get_or_create(successful=object_data['successful'], question=dns_question_object)
            # add observable
            dns_query_object.observables.add(observable_object)
            dns_query_object.save()
            # create object ID mapping
            if object_id in self.id_mapping['objects']:
                self.id_mapping['objects'][object_id].append({'object_id': dns_query_object.id, 'object_type': object_type})
            else:
                self.id_mapping['objects'][object_id] = [{'object_id': dns_query_object.id, 'object_type': object_type}]
            object_list.append(dns_query_object)
        elif object_type == 'WindowsExecutableFileObjectType':
            executable_dict = handle_windows_executable_object(object_data, object_id)
            # get imports list
            imports_dict_list = executable_dict.pop('imports')
            # get exports list
            exports_dict_list = executable_dict.pop('exports')
            # get sections list
            sections_dict_list = executable_dict.pop('sections')
            # create windows executable object
            win_exec_obj, win_exec_obj_created = WindowsExecutable_Object.objects.get_or_create(**executable_dict)
            # add imports
            for imp in imports_dict_list:
                pe_import_obj, pe_import_created = PEImports.objects.get_or_create(**{'file_name': imp['file_name'], 'virtual_address': imp['virtual_address']})
                for imp_func in imp['imported_functions']:
                    imp_func_obj, imp_func_created = ImportedFunction.objects.get_or_create(**{'function_name': imp_func['function_name'], 'virtual_address': imp_func['virtual_address']})
                    pe_import_obj.imported_functions.add(imp_func_obj)
                pe_import_obj.save()
                win_exec_obj.imports.add(pe_import_obj)
            # add exports
            for emp in exports_dict_list:
                pe_export_obj, pe_export_created = PEExports.objects.get_or_create(**{'name': emp['name']})
                for emp_func in emp['exported_functions']:
                    emp_func_obj, emp_func_created = ExportedFunction.objects.get_or_create(**{'function_name': emp_func['function_name'], 'entry_point': emp_func['entry_point']})
                    pe_export_obj.exported_functions.add(emp_func_obj)
                pe_export_obj.save()
                win_exec_obj.exports.add(pe_export_obj)
            # add sections
            for sec in sections_dict_list:
                sec_obj, sec_created = PESections.objects.get_or_create(**{'section_name': sec.get('section_name', 'None'), 'entropy': sec.get('entropy', 0.0), 'virtual_size': sec.get('virtual_size', 'None'), 'virtual_address': sec.get('virtual_address', 'None'), 'size_of_raw_data': sec.get('size_of_raw_data', 'None')})
                win_exec_obj.sections.add(sec_obj)
            # add observable
            win_exec_obj.observables.add(observable_object)
            win_exec_obj.save()
            # create object ID mapping
            if object_id in self.id_mapping['objects']:
                self.id_mapping['objects'][object_id].append({'object_id': win_exec_obj.id, 'object_type': object_type})
            else:
                self.id_mapping['objects'][object_id] = [{'object_id': win_exec_obj.id, 'object_type': object_type}]
            object_list.append(win_exec_obj)
        else:
            self.missed_objects[object_type] = True
        return object_list

    def extract_observable_data(self, observable, first_entry, package_object, indicator_object=None):
        """create database entry for given observable and check for related object
        @observable: observable to create a database entry for
        @first_entry: boolean that is used for output to the console
        @package_object: base object that represents the stix package
        @indicator_object: if observable is embedded in an indicator else None
        returns: tuple
        """
        # get ID and namespace
        observable_id = observable['id']
        observable_namespace_obj = self.get_full_namespace2(observable_id.split(':', 1)[0])
        # determine object type and get object ID
        if 'object' in observable and 'properties' in observable['object']:
            object_type = observable['object']['properties']['xsi:type']
            if 'id' in observable['object']:
                object_id = observable['object']['id']
            else:
                object_id = observable_id
        elif 'observable_composition' in observable:
            # handle observable composition
            composition_object = self.create_observable_composition(observable, observable_id, None, None)
            # check if observable already exists
            if observable_id in self.id_mapping['observables']:
                observable_object = Observable.objects.get(id=self.id_mapping['observables'][observable_id])
                observable_created = False
            else:
                # create dummy observable to attach composition to
                observable_dict = {
                    'name': observable.get('title', observable_id),
                    'description': 'Observable Composition Container',
                    'short_description': 'Observable Composition Container',
                    'observable_type': 'CompositionContainer',
                    'observable_id': observable_id
                }
                # check if database object with same ID already exists and update
                try:
                    Observable.objects.filter(observable_id=observable_id).update(**observable_dict)
                    observable_object = Observable.objects.get(observable_id=observable_id)
                    observable_created = False
                except Observable.DoesNotExist:
                    observable_object, observable_created = Observable.objects.get_or_create(**observable_dict)
                observable_object.namespace.add(observable_namespace_obj)
                # create observable mapping
                self.id_mapping['observables'][observable_id] = observable_object.id
            # add composition
            observable_object.compositions.add(composition_object)
            # add to package
            package_object.observables.add(observable_object)
            return first_entry, package_object
        else:
            object_type = None
            if first_entry:
                self.stdout.write('[ERROR]')
                first_entry = False
            self.stdout.write('----> observable without object element and type description (%s)' % (observable_id))
            return first_entry, package_object
        # check if observable already exists
        if observable_id in self.id_mapping['observables']:
            observable_object = Observable.objects.get(id=self.id_mapping['observables'][observable_id])
            observable_created = False
        else:
            # create observable object
            observable_dict = {
                'name': observable.get('title', observable_id),
                'description': observable.get('description', 'No Description'),
                'short_description': observable.get('short_description', 'No Short Description'),
                'observable_type': object_type,
                'observable_id': observable_id
            }
            # check if database object with same ID already exists and update
            try:
                Observable.objects.filter(observable_id=observable_id).update(**observable_dict)
                observable_object = Observable.objects.get(observable_id=observable_id)
                observable_created = False
            except Observable.DoesNotExist:
                observable_object, observable_created = Observable.objects.get_or_create(**observable_dict)
            observable_object.namespace.add(observable_namespace_obj)
            # create observable mapping
            self.id_mapping['observables'][observable_id] = observable_object.id
        # add to package
        package_object.observables.add(observable_object)
        # add to indicator if available
        if indicator_object:
            observable_object.indicators.add(indicator_object)
        # check if object already exists
        if object_id in self.id_mapping['objects']:
            object_list = []
            for object_db_dict in self.id_mapping['objects'][object_id]:
                db_object = self.get_database_object(**object_db_dict)
                # add observable
                db_object.observables.add(observable_object)
                object_list.append(db_object)
            db_object.save()
        else:
            object_list = self.determine_create_object(observable_object, object_type, observable['object']['properties'], object_id)
        # check for related objects
        if object_type and 'related_objects' in observable['object']:
            for related_object in observable['object']['related_objects']:
                for object_one in object_list:
                    related_object_dict = {
                        'relationship': 'contains',
                        'object_one_id': object_one.id,
                        'object_one_type': object_type,
                        'object_two_id': None,
                        'object_two_type': None
                    }
                    # get relationship information
                    if 'relationship' in related_object:
                        if isinstance(related_object['relationship'], dict):
                            related_object_dict['relationship'] = related_object['relationship'].get('value', 'contains')
                        else:
                            related_object_dict['relationship'] = related_object['relationship']
                    # check if it is a reference or a complete object
                    if 'idref' in related_object:
                        try:
                            stored_object_list = self.id_mapping['objects'][related_object['idref']]
                        except KeyError as e:
                            try:
                                self.missing_references['object_2_object'][object_id].append({
                                    'id': related_object['idref'],
                                    'relationship': related_object_dict['relationship']
                                })
                            except:
                                self.missing_references['object_2_object'][object_id] = [{
                                    'id': related_object['idref'],
                                    'relationship': related_object_dict['relationship']
                                }]
                            stored_object_list = []
                        for object_dict in stored_object_list:
                            if object_dict:
                                related_object_dict['object_two_id'] = object_dict['object_id']
                                related_object_dict['object_two_type'] = object_dict['object_type']
                                object_db_relation, created = Related_Object.objects.get_or_create(**related_object_dict)
                    elif 'id' in related_object and 'properties' in related_object and 'xsi:type' in related_object['properties']:
                        # create new object and link it
                        related_object_id = related_object['id']
                        related_object_type = related_object['properties']['xsi:type']
                        # check if object already exists
                        if related_object_id in self.id_mapping['objects']:
                            related_object_list = []
                            for related_object_db_dict in self.id_mapping['objects'][related_object_id]:
                                related_db_object = self.get_database_object(**related_object_db_dict)
                                # add observable
                                related_db_object.observables.add(observable_object)
                                related_object_list.append(related_db_object)
                            related_db_object.save()
                        else:
                            related_object_list = self.determine_create_object(observable_object, related_object_type, related_object['properties'], related_object_id)
                        for related_item in related_object_list:
                            # create object relation
                            related_object_dict['object_two_id'] = related_item.id
                            related_object_dict['object_two_type'] = related_object_type
                            object_db_relation, created = Related_Object.objects.get_or_create(**related_object_dict)
                    else:
                        if first_entry:
                            self.stdout.write('[WARNING]')
                            first_entry = False
                        self.stdout.write("----> related object without ID found")
        return first_entry, package_object

    def create_observable_composition(self, composition_json, composition_id=None, indicator=None, observable=None):
        """recursively check for observable composition objects
        @composition_json: json representation of an observable composition
        @composition_id: identifier/name for the observable composition (first takes the name of the indicator embedded in)
        @indicator: indicator object that contains the observable composition
        """
        composition_dict = {
            'name': composition_id,
            'operator': 'OR'
        }
        # check for id and set it as name
        if "id" in composition_json:
            composition_dict['name'] = composition_json["id"]
        # check for operator
        if "observable_composition" in composition_json and "operator" in composition_json['observable_composition']:
            composition_dict['operator'] = composition_json['observable_composition']['operator']
        # create composition object
        composition_object, composition_object_created = ObservableComposition.objects.get_or_create(**composition_dict)
        # add mapping
        self.id_mapping['compositions'][composition_id] = composition_object.id
        if indicator:
            composition_object.indicator.add(indicator)
        # check for observables
        if "observable_composition" in composition_json and "observables" in composition_json['observable_composition']:
            for observable_item in composition_json['observable_composition']['observables']:
                if "idref" in observable_item:
                    if observable_item['idref'] in self.id_mapping['observables']:
                        # add related indicator to observable
                        observable_object = Observable.objects.get(id=self.id_mapping['observables'][observable_item['idref']])
                        composition_object.observables.add(observable_object)
                    else:
                        try:
                            observable_object = Observable.objects.get(observable_id=observable_item['idref'])
                            composition_object.observables.add(observable_object)
                        except Observable.DoesNotExist:
                            try:
                                self.missing_references['composite_2_observable'][composition_id].append(observable_item['idref'])
                            except:
                                self.missing_references['composite_2_observable'][composition_id] = [observable_item['idref']]
                elif "id" and "observable_composition" in observable_item:
                    composition_object.observable_compositions.add(self.create_observable_composition(observable_item, observable_item['id'], None, None))
                else:
                    print observable_item
        composition_object.save()
        return composition_object


    def perform_indicator_extraction(self, stix_json, package_object):
        """iterate over indicators and extract observable information and create indicator object
        @stix_json: json representation of a stix report
        @package_object: base object that represents the stix package
        returns: package db object
        """
        self.stdout.write('--> extracting indicator information ... ', ending='')
        sys.stdout.flush()
        first_entry = True
        for indicator in stix_json['indicators']:
            indicator_id = indicator['id']
            indicator_namespace_obj = self.get_full_namespace2(indicator_id.split(':', 1)[0])
            # check if indicator already exists
            if indicator_id in self.id_mapping['indicators']:
                indicator_object = Indicator.objects.get(id=self.id_mapping['indicators'][indicator_id])
                indicator_object_created = False
            else:
                indicator_dict = {
                    'name': indicator.get('title', indicator_id),
                    'description': indicator.get('description', 'No Description'),
                    'short_description': indicator.get('short_description', 'No Short Description'),
                    'indicator_id': indicator_id
                }
                # create indicator object
                indicator_object, indicator_object_created = Indicator.objects.get_or_create(**indicator_dict)
                indicator_object.namespace.add(indicator_namespace_obj)
                # create observable mapping
                self.id_mapping['indicators'][indicator_id] = indicator_object.id
            # add to package
            package_object.indicators.add(indicator_object)
            # create indicator types
            if 'indicator_types' in indicator:
                for indicator_type in indicator['indicator_types']:
                    if isinstance(indicator_type, dict):
                        indicator_type_object, indicator_type_created = Indicator_Type.objects.get_or_create(itype=indicator_type.get('value', 'No Type'))
                    else:
                        indicator_type_object, indicator_type_created = Indicator_Type.objects.get_or_create(itype=indicator_type)
                    indicator_object.indicator_types.add(indicator_type_object)
                indicator_object.save()
                # remove from indicator object since it is done
                indicator.pop('indicator_types')
            # create indicator kill chain phase
            if 'kill_chain_phases' in indicator:
                if 'kill_chain_phases' in indicator['kill_chain_phases']:
                    for phase in indicator['kill_chain_phases']['kill_chain_phases']:
                        phase_dict = {
                            'name': phase.get('name', 'Not Set'),
                            'ordinality': phase.get('ordinality', 0)
                        }
                        kcp_object, kcp_created = Indicator_Kill_Chain_Phase.objects.get_or_create(**phase_dict)
                        indicator_object.kill_chain_phases.add(kcp_object)
                    indicator_object.save()
                    # remove from indicator json
                    indicator.pop('kill_chain_phases')
            # create confidence object
            confidence_dict = {
                'value': 'Low',
                'description': 'No Description'
            }
            if 'confidence' in indicator and 'value' in indicator['confidence']:
                confidence_dict['value'] = indicator['confidence']['value'].get('value', 'Low')
                confidence_dict['description'] = indicator['confidence'].get('description', 'No Description')
                # remove from indicator object since it is done
                indicator.pop('confidence')
            confidence_object, confidence_created = Confidence.objects.get_or_create(**confidence_dict)
            indicator_object.confidence.add(confidence_object)
            indicator_object.save()

            # check for observables
            if 'observable' in indicator:
                # check if composite observable is present
                if 'observable_composition' in indicator['observable']:
                    self.create_observable_composition(indicator['observable'], indicator_object.name, indicator_object, None)
                # check for observable reference
                if 'idref' in indicator['observable']:
                    if indicator['observable']['idref'] in self.id_mapping['observables']:
                        # add related indicator to observable
                        observable_object = Observable.objects.get(id=self.id_mapping['observables'][indicator['observable']['idref']])
                        observable_object.indicators.add(indicator_object)
                        observable_object.save()
                    else:
                        # check if database entry with given IDREF exists
                        try:
                            observable_object = Observable.objects.get(observable_id=indicator['observable']['idref'])
                            observable_object.indicators.add(indicator_object)
                            observable_object.save()
                        except Observable.DoesNotExist:
                            self.missing_references['indicator_2_observable'][indicator_id] = indicator['observable']['idref']
                elif 'id' in indicator['observable']:
                    # create new observable and object entry
                    first_entry, package_object = self.extract_observable_data(indicator['observable'], first_entry, package_object, indicator_object)
                # remove from indicator object since it is done
                indicator.pop('observable')
            # check for composite indicator
            if 'composite_indicator_expression' in indicator and 'indicators' in indicator['composite_indicator_expression']:
                composite_operator = indicator['composite_indicator_expression'].get('operator', 'OR')
                indicator_object.indicator_composition_operator = composite_operator
                indicator_object.save()
                for composite_indicator_ref in indicator['composite_indicator_expression']['indicators']:
                    composite_indicator_idref = composite_indicator_ref['idref']
                    # check if indicator already exists
                    if composite_indicator_idref in self.id_mapping['indicators']:
                        composite_indicator_object = Indicator.objects.get(id=self.id_mapping['indicators'][composite_indicator_idref])
                        indicator_object.related_indicators.add(composite_indicator_object)
                    else:
                        try:
                            self.missing_references['indicator_2_indicator'][indicator_id].append(composite_indicator_idref)
                        except:
                            self.missing_references['indicator_2_indicator'][indicator_id] = [composite_indicator_idref]
                # add composite type to indicator
                indicator_type_object, indicator_type_created = Indicator_Type.objects.get_or_create(itype='Composite')
                indicator_object.indicator_types.add(indicator_type_object)
                indicator_object.save()
                indicator.pop('composite_indicator_expression')
            # check for indicated ttps
            if 'indicated_ttps' in indicator:
                for ittp_dict in indicator['indicated_ttps']:
                    if 'ttp' in ittp_dict:
                        ittp = ittp_dict['ttp']
                        # check for referenced ttp or inline ttp
                        if 'idref' in ittp:
                            ttp_idref = ittp['idref']
                            if ttp_idref in self.id_mapping['ttps']:
                                ttp_object = TTP.objects.get(id=self.id_mapping['ttps'][ttp_idref])
                                indicator_object.ttps.add(ttp_object)
                            else:
                                try:
                                    self.missing_references['indicator_2_ttp'][indicator_id].append(ttp_idref)
                                except:
                                    self.missing_references['indicator_2_ttp'][indicator_id] = [ttp_idref]
                        else:
                            pass
                indicator_object.save()
                indicator.pop('indicated_ttps')
            # Indicator Timestamp
            if 'timestamp' in indicator:
                indicator_object.produced_time = date_parser(indicator['timestamp']).replace(tzinfo=pytz.UTC)
                indicator_object.save()
                indicator.pop('timestamp')
            # DEBUG print
            #if len(indicator)>3:
            #    print json.dumps(indicator, indent=4, sort_keys=True)
            # add missed elements
            for element in indicator.keys():
                if element not in self.common_elements:
                    self.missed_elements['indicator'][element] = True
        if first_entry:
            self.stdout.write('[DONE]')
        return package_object

    def perform_observable_extraction(self, stix_json, package_object):
        """ iterate over all observables in stix document and generate according database objects
        @stix_json: json representation of a stix report
        @package_object: base object that represents the stix package
        returns: package db object
        """
        self.stdout.write('--> extracting observable information ... ', ending='')
        sys.stdout.flush()
        first_entry = True
        if not 'observables' in stix_json['observables']:
            self.stdout.write('[FAIL]')
            return package_object
        # iterate over observables
        for observable in stix_json['observables']['observables']:
            first_entry, package_object = self.extract_observable_data(observable, first_entry, package_object)
        # remove already processed information
        stix_json['observables'].pop('observables')
        # add missed elements
        for element in stix_json['observables'].keys():
            if element not in self.common_elements:
                self.missed_elements['observable'][element] = True
        if first_entry:
            self.stdout.write('[DONE]')
        return package_object

    def perform_ttp_extraction(self, stix_json, package_object):
        """iterate over ttps and extract ttp information and create ttp object
        @stix_json: json representation of a stix report
        @package_object: base object that represents the stix package
        returns: package db object
        """
        self.stdout.write('--> extracting ttp information ... ', ending='')
        sys.stdout.flush()
        first_entry = True
        if not 'ttps' in stix_json['ttps']:
            self.stdout.write('[FAIL]')
            # add missed elements
            for element in stix_json['ttps'].keys():
                if element not in self.common_elements:
                    self.missed_elements['ttps'][element] = True
            #print json.dumps(stix_json['ttps'], indent=4, sort_keys=True)
            return package_object
        # iterate over ttp elements
        for ttp in stix_json['ttps']['ttps']:
            if not 'id' in  ttp:
                continue
            ttp_id = ttp['id']
            ttp_namespace_obj = self.get_full_namespace2(ttp_id.split(':', 1)[0])
            # check if ttp already exists
            if ttp_id in self.id_mapping['ttps']:
                ttp_object = TTP.objects.get(id=self.id_mapping['ttps'][ttp_id])
                ttp_object_created = False
            else:
                # get ttp name
                if 'title' in ttp:
                    ttp_name = ttp.get('title', ttp_id)
                else:
                    ttp_name = ttp_id
                ttp_dict = {
                    'name': ttp_name,
                    'description': ttp.get('description', 'No Description'),
                    'short_description': ttp.get('short_description', 'No Short Description'),
                    'ttp_id': ttp_id
                }
                # create ttp object
                ttp_object, ttp_object_created = TTP.objects.get_or_create(**ttp_dict)
                ttp_object.namespace.add(ttp_namespace_obj)
                # create ttp mapping
                self.id_mapping['ttps'][ttp_id] = ttp_object.id
            # add to package
            package_object.ttps.add(ttp_object)
            # check for related ttps
            if 'related_ttps' in ttp:
                for related_ttp_json in ttp['related_ttps']['ttps']:
                    if 'ttp' in related_ttp_json and 'idref' in related_ttp_json['ttp']:
                        # check if related ttp already exists
                        if 'relationship' in related_ttp_json:
                            ttp_relationship = related_ttp_json['relationship']
                        else:
                            ttp_relationship = 'Unknown Relation'
                        related_ttp_id = related_ttp_json['ttp']['idref']
                        if related_ttp_id in self.id_mapping['ttps']:
                            related_ttp_object = TTP.objects.get(id=self.id_mapping['ttps'][related_ttp_id])
                            ttp_object.add_related_ttp(related_ttp_object, ttp_relationship)
                            ttp_object.save()
                        else:
                            try:
                                self.missing_references['ttp_2_ttp'][ttp_id].append((related_ttp_id, ttp_relationship))
                            except:
                                self.missing_references['ttp_2_ttp'][ttp_id] = [(related_ttp_id, ttp_relationship)]
                    else:
                        self.stdout.write('----> ERROR: inline related TTP not handled yet!')
                        first_entry = False
                ttp.pop('related_ttps')
            # check for behavior elements
            if 'behavior' in ttp:
                for behavior_type in ttp['behavior']:
                    if behavior_type == 'malware_instances':
                        for mw_instance in ttp['behavior']['malware_instances']:
                            pre_mw_description = mw_instance.get('description', 'No Description')
                            if isinstance(pre_mw_description, dict):
                                mw_description = pre_mw_description.get('value', 'No Description')
                            else:
                                mw_description = pre_mw_description
                            mw_instance_dict = {
                                'ttp_ref': ttp_object,
                                'name': mw_instance.get('title', 'No Title'),
                                'description': mw_description,
                                'short_description': mw_instance.get('short_description', 'No Short Description'),
                            }
                            mw_instance_object, mw_instance_object_created = MalwareInstance.objects.get_or_create(**mw_instance_dict)
                            if 'names' in mw_instance:
                                for name in mw_instance['names']:
                                    mw_names_object, mw_names_object_created = MalwareInstanceNames.objects.get_or_create(instance_ref=mw_instance_object, name=name)
                            if 'types' in mw_instance:
                                for _type in mw_instance['types']:
                                    #  _type instance of dictionary
                                    if isinstance(_type, dict):
                                        mw_types_object, mw_types_object_created = MalwareInstanceTypes.objects.get_or_create(instance_ref=mw_instance_object,           _type=_type['value'])
                                    else:
                                        mw_types_object, mw_types_object_created = MalwareInstanceTypes.objects.get_or_create(instance_ref=mw_instance_object, _type=_type)
                    elif behavior_type == 'attack_patterns':
                        for pattern in ttp['behavior']['attack_patterns']:
                            pre_ap_description = pattern.get('description', 'No Description')
                            if isinstance(pre_ap_description, dict):
                                ap_description = pre_ap_description.get('value', 'No Description')
                            else:
                                ap_description = pre_ap_description
                            pattern_dict = {
                                'ttp_ref': ttp_object,
                                'name': pattern.get('title', 'No Title'),
                                'description': ap_description,
                                'short_description': pattern.get('short_description', 'No Short Description'),
                                'capec_id': pattern.get('capec_id', 'No Capec ID'),
                            }
                            pattern_object, pattern_object_created = AttackPattern.objects.get_or_create(**pattern_dict)
                    else:
                        self.missed_elements['ttps'][behavior_type] = True
                #ttp.pop('behavior')
            # add missed elements
            for element in ttp.keys():
                if element not in self.common_elements:
                    self.missed_elements['ttps'][element] = True
        if first_entry:
            self.stdout.write('[DONE]')
        # DEBUG output for TTP
        print json.dumps(ttp, indent=4, sort_keys=True)
        return package_object

    def perform_campaign_extraction(self, stix_json, package_object):
        """iterate over campaigns and extract campaign information and create campaign object
        @stix_json: json representation of a stix report
        @package_object: base object that represents the stix package
        returns: package db object
        """
        self.stdout.write('--> extracting campaign information ... ', ending='')
        sys.stdout.flush()
        first_entry = True
        # iterate over campaign elements
        for campaign in stix_json['campaigns']:
            campaign_id = campaign['id']
            campaign_namespace_obj = self.get_full_namespace2(campaign_id.split(':', 1)[0])
            # check if campaign already exists
            if campaign_id in self.id_mapping['campaigns']:
                campaign_object = Campaign.objects.get(id=self.id_mapping['campaigns'][campaign_id])
                campaign_object_created = False
            else:
                # get campaign name
                if 'title' in campaign:
                    campaign_name = campaign.get('title', campaign_id)
                else:
                    campaign_name = campaign_id
                campaign_dict = {
                    'name': campaign_name,
                    'description': campaign.get('description', 'No Description'),
                    'short_description': campaign.get('short_description', 'No Short Description'),
                    'status': campaign.get('status', 'Ongoing'),
                    'campaign_id': campaign_id
                }
                # create campaign object
                campaign_object, campaign_object_created = Campaign.objects.get_or_create(**campaign_dict)
                campaign_object.namespace.add(campaign_namespace_obj)
                # create campaign mapping
                self.id_mapping['campaigns'][campaign_id] = campaign_object.id
            # add to package
            package_object.campaigns.add(campaign_object)
            # remove status as it has been already used
            if 'status' in campaign:
                campaign.pop('status')
            # check for related ttps
            if 'related_ttps' in campaign and 'ttps' in campaign['related_ttps']:
                for related_ttp in campaign['related_ttps']['ttps']:
                    # get relationship information
                    if 'relationship' in related_ttp:
                        ttp_relationship = related_ttp['relationship']
                    else:
                        ttp_relationship = 'Unknown Relation'
                    related_ttp_id = related_ttp['ttp']['idref']
                    if related_ttp_id in self.id_mapping['ttps']:
                        related_ttp_object = TTP.objects.get(id=self.id_mapping['ttps'][related_ttp_id])
                        campaign_object.add_related_ttp(related_ttp_object, ttp_relationship)
                        campaign_object.save()
                    else:
                        try:
                            self.missing_references['campaign_2_ttp'][campaign_id].append((related_ttp_id, ttp_relationship))
                        except:
                            self.missing_references['campaign_2_ttp'][campaign_id] = [(related_ttp_id, ttp_relationship)]
                campaign.pop('related_ttps')
            # add missed elements
            for element in campaign.keys():
                if element not in self.common_elements:
                    self.missed_elements['campaign'][element] = True
        if first_entry:
            self.stdout.write('[DONE]')
        # DEBUG Output
        #print json.dumps(campaign, indent=4, sort_keys=True)
        return package_object

    def perform_threat_actor_extraction(self, stix_json, package_object):
        """ iterate over all threat actors in stix document and generate according database objects
        @stix_json: json representation of a stix report
        @package_object: base object that represents the stix package
        returns: package db object
        """
        self.stdout.write('--> extracting threat actor information ... ', ending='')
        sys.stdout.flush()
        first_entry = True
        # iterate over threat actor elements
        for threat_actor in  stix_json['threat_actors']:
            threat_actor_id = threat_actor['id']
            threat_actor_namespace_obj = self.get_full_namespace2(threat_actor_id.split(':', 1)[0])
            # check if threat actor already exists
            if threat_actor_id in self.id_mapping['threat_actors']:
                threat_actor_object = ThreatActor.objects.get(id=self.id_mapping['threat_actors'][threat_actor_id])
                threat_actor_object_created = False
            else:
                # get threat actor name
                if 'title' in threat_actor:
                    threat_actor_name = threat_actor.get('title', threat_actor_id)
                elif 'identity' in threat_actor and 'name' in threat_actor['identity']:
                    threat_actor_name = threat_actor['identity']['name']
                else:
                    threat_actor_name = threat_actor_id
                threat_actor_dict = {
                    'name': threat_actor_name,
                    'description': threat_actor.get('description', 'No Description'),
                    'short_description': threat_actor.get('short_description', 'No Short Description'),
                    'threat_actor_id': threat_actor_id
                }
                # create threat actor object
                threat_actor_object, threat_actor_object_created = ThreatActor.objects.get_or_create(**threat_actor_dict)
                threat_actor_object.namespace.add(threat_actor_namespace_obj)
                # create threat actor mapping
                self.id_mapping['threat_actors'][threat_actor_id] = threat_actor_object.id
            # add to package
            package_object.threat_actors.add(threat_actor_object)
            # create threat actor roles
            if 'identity' in threat_actor and 'roles' in threat_actor['identity']:
                for role in threat_actor['identity']['roles']:
                    ta_role_object, ta_role_object_created = TA_Roles.objects.get_or_create(role=role, actor=threat_actor_object)
            # create threat actor alias
            if 'identity' in threat_actor and 'specification' in threat_actor['identity'] and 'party_name' in threat_actor['identity']['specification']:
                if 'organisation_names' in threat_actor['identity']['specification']['party_name']:
                    for organization in threat_actor['identity']['specification']['party_name']['organisation_names']:
                        alias_type = organization.get('type', 'UnofficialName')
                        alias_list = organization.get('name_elements', [])
                        for alias_item in alias_list:
                            # create threat actor alias object
                            ta_alias_object, ta_alias_object_created = TA_Alias.objects.get_or_create(
                                alias=alias_item.get('value', 'No Name'),
                                actor=threat_actor_object,
                                alias_type=alias_type
                            )
                            ta_alias_object.namespace.add(threat_actor_namespace_obj)
                if 'person_names' in threat_actor['identity']['specification']['party_name']:
                    for person in threat_actor['identity']['specification']['party_name']['person_names']:
                        alias_type = person.get('type', 'UnofficialName')
                        alias_list = person.get('name_elements', [])
                        for alias_item in alias_list:
                            # create threat actor alias object
                            ta_alias_object, ta_alias_object_created = TA_Alias.objects.get_or_create(
                                alias=alias_item.get('value', 'No Name'),
                                actor=threat_actor_object,
                                alias_type=alias_type
                            )
                            ta_alias_object.namespace.add(threat_actor_namespace_obj)
            # create threat actor alias (part 2)
            if 'identity' in threat_actor and 'name' in threat_actor['identity']:
                ta_alias_object, ta_alias_object_created = TA_Alias.objects.get_or_create(
                    alias=threat_actor['identity']['name'],
                    actor=threat_actor_object,
                )
                ta_alias_object.namespace.add(threat_actor_namespace_obj)
            # last access to identity -> remove element
            if 'identity' in threat_actor:
                threat_actor.pop('identity')
            # create associated threat actors
            if 'associated_actors' in threat_actor and 'threat_actors' in threat_actor['associated_actors']:
                for associated_actor in threat_actor['associated_actors']['threat_actors']:
                    associated_actor_id = associated_actor['threat_actor']['idref']
                    # check if associated actor object already exists
                    if associated_actor_id in self.id_mapping['threat_actors']:
                        associated_actor_object = ThreatActor.objects.get(id=self.id_mapping['threat_actors'][associated_actor_id])
                        threat_actor_object.associated_threat_actors.add(associated_actor_object)
                    else:
                        try:
                            self.missing_references['actor_2_actor'][threat_actor_id].append(associated_actor_id)
                        except:
                            self.missing_references['actor_2_actor'][threat_actor_id] = [associated_actor_id]
                threat_actor_object.save()
                threat_actor.pop('associated_actors')
            # create threat actor types
            if 'types' in threat_actor:
                for ta_type in threat_actor['types']:
                    ta_type_object, ta_type_object_created = TA_Types.objects.get_or_create(
                        ta_type=ta_type['value'],
                        actor=threat_actor_object,
                    )
                threat_actor.pop('types')
            # create associated campaigns
            if 'associated_campaigns' in threat_actor and 'campaigns' in threat_actor['associated_campaigns']:
                for associated_campaign in threat_actor['associated_campaigns']['campaigns']:
                    associated_campaign_id = associated_campaign['campaign']['idref']
                    # check if associated campaign already exists
                    if associated_campaign_id in self.id_mapping['campaigns']:
                        associated_campaign_object = Campaign.objects.get(id=self.id_mapping['campaigns'][associated_campaign_id])
                        threat_actor_object.campaigns.add(associated_campaign_object)
                    else:
                        try:
                            self.missing_references['actor_2_campaign'][threat_actor_id].append(associated_campaign_id)
                        except:
                            self.missing_references['actor_2_campaign'][threat_actor_id] = [associated_campaign_id]
                threat_actor_object.save()
                threat_actor.pop('associated_campaigns')
            # create observed ttps
            if 'observed_ttps' in threat_actor and 'ttps' in threat_actor['observed_ttps']:
                for observed_ttp in threat_actor['observed_ttps']['ttps']:
                    # get relationship information
                    if 'relationship' in observed_ttp:
                        ttp_relationship = observed_ttp['relationship']
                    else:
                        ttp_relationship = 'Unknown Relation'
                    if 'idref' in observed_ttp['ttp']:
                        observed_ttp_id = observed_ttp['ttp']['idref']
                        if observed_ttp_id in self.id_mapping['ttps']:
                            observed_ttp_object = TTP.objects.get(id=self.id_mapping['ttps'][observed_ttp_id])
                            threat_actor_object.add_observed_ttp(observed_ttp_object, ttp_relationship)
                            threat_actor_object.save()
                        else:
                            try:
                                self.missing_references['actor_2_ttp'][threat_actor_id].append((observed_ttp_id, ttp_relationship))
                            except:
                                self.missing_references['actor_2_ttp'][threat_actor_id] = [(observed_ttp_id, ttp_relationship)]
                    else:
                        # inline TTP ? TODO
                        print "INLINE TTP !!!"
                        print json.dumps(observed_ttp, indent=4, sort_keys=True)
                        continue
                threat_actor.pop('observed_ttps')
            # add missed elements
            for element in threat_actor.keys():
                if element not in self.common_elements:
                    self.missed_elements['threat_actor'][element] = True
        if first_entry:
            self.stdout.write('[DONE]')
        # DEBUG Output
        #print json.dumps(threat_actor, indent=4, sort_keys=True)
        return package_object

    def get_full_namespace2(self, ns):
        """ iterate over list of XML namespaces to find the appropriate one
        and return namespace object
        """
        for nsurl, nsname in self.stix_namespaces_dict.iteritems():
            if nsname == ns:
                ns_obj, ns_created = Namespace.objects.get_or_create(namespace="%s:%s" % (nsname, nsurl))
                return ns_obj
        ns_obj, ns_created = Namespace.objects.get_or_create(namespace="%s:%s" % (ns, 'empty'))
        return ns_obj


    def get_full_namespace(self, ns):
        """ iterate over list of XML namespaces to find the appropriate one
        and return the complete namespace string
        """
        for nsurl, nsname in self.stix_namespaces_dict.iteritems():
            if nsname == ns:
                return "%s:%s" % (nsname, nsurl)
        return "%s:%s" % (ns, 'empty')

    def perform_stix_header_extraction(self, stix_json):
        """ examine the stix header and base information to create a package object
        @stix_json: json representation of a stix report
        returns: package db object
        """
        self.stdout.write('--> extracting stix package information ... ', ending='')
        sys.stdout.flush()
        first_entry = True

        TAG_RE = re.compile(r'<[^>]+>')

        if 'stix_header' in stix_json:
            title = stix_json['stix_header'].get('title', 'No Title')
            if 'description' in stix_json['stix_header']:
                if isinstance(stix_json['stix_header']['description'], dict):
                    description = stix_json['stix_header']['description'].get('value', 'No Description').strip()
                else:
                    description = stix_json['stix_header'].get('description', 'No Description').strip()
            else:
                description = 'No Description'
            short_description = stix_json['stix_header'].get('short_description', 'No Short Description')
            if 'information_source' in stix_json['stix_header'] and 'identity' in stix_json['stix_header']['information_source']:
                source = stix_json['stix_header']['information_source']['identity'].get('name', 'No Source')
            else:
                source = 'No Source'
            if 'information_source' in stix_json['stix_header'] and 'time' in stix_json['stix_header']['information_source']:
                produced_time = stix_json['stix_header']['information_source']['time'].get('produced_time', None)
            else:
                produced_time = None
        else:
            title = stix_json['id']
            description = 'No Description'
            short_description = 'No Short Description'
            source = 'No Source'
            produced_time = None
        if produced_time:
            produced_time = date_parser(produced_time).replace(tzinfo=pytz.UTC)
        else:
            ### try to get produced time from timestamp field
            if 'timestamp' in stix_json:
                produced_time = date_parser(stix_json['timestamp']).replace(tzinfo=pytz.UTC)

        package_id = stix_json['id']
        if title == 'No Title':
            title = package_id
        package_namespace_obj = self.get_full_namespace2(stix_json['id'].split(':', 1)[0])
        package_dict = {
            'package_id': package_id,
            'version': stix_json['version'],
            'name': title,
            'description': TAG_RE.sub('', description).strip(),
            'short_description': short_description,
            'source': source,
        }
        if produced_time:
            package_dict['produced_time'] = produced_time
        # create package db object
        package_object, package_object_created = Package.objects.get_or_create(**package_dict)
        package_object.namespace.add(package_namespace_obj)
        # get package intents
        if 'stix_header' in stix_json and 'package_intents' in stix_json['stix_header']:
            for intent in stix_json['stix_header']['package_intents']:
                if isinstance(intent, dict):
                    intent_value = intent.get('value', 'No Intent')
                else:
                    intent_value = intent
                intent_object, intent_object_created = Package_Intent.objects.get_or_create(intent=intent_value, package=package_object)
        # get package references
        if 'stix_header' in stix_json and 'information_source' in stix_json['stix_header'] and 'references' in stix_json['stix_header']['information_source']:
            for reference in stix_json['stix_header']['information_source']['references']:
                reference_object, reference_object_created = Package_Reference.objects.get_or_create(reference=reference, package=package_object)

        if first_entry:
            self.stdout.write('[DONE]')
        return package_object

    def iterate_xml(self, xml, parser):
        """try to parse xml and extract information
        @xml: path to xml file to parse
        @parser: stix entity parser to parse stix xml structure
        returns: list of stix packages in json format
        """
        result_list = []
        try:
            self.stdout.write('reading xml: %s ... ' % (xml), ending='')
            sys.stdout.flush()
            stix_object = parser.parse_xml(xml, check_version=False)
            stix_namespaces = stix_object.__input_namespaces__
            stix_json = json.loads(stix_object.to_json())
            result_list.append((stix_json, stix_namespaces))
            self.stdout.write('[DONE]')
            del stix_object
        except Exception as e:
            self.stdout.write('[FAIL]')
            self.stdout.write('Failed parsing stix XML: %s' % (e))
            failed = True
            try:
                fp = open(xml)
                xml_content = fp.read()
                fp.close()
            except Exception as e:
                xml_content = None
                self.stdout.write('Failed opening XML: %s (%s)' % (xml, e))
            if xml_content and xml_content.count(':STIX_Packages>')>0:
                self.stdout.write('Found possible multiple STIX package construct ...')
                patch = False
                # check for older format
                if xml_content.count('stix="http://stix.mitre.org"')>0:
                    self.stdout.write('----> old STIX Package Format found ... requires patching')
                    patch = True
                from lxml import etree
                from io import StringIO
                tree = etree.parse(xml)
                root = tree.getroot()
                for child in root:
                    if patch:
                        child.tag = "{http://stix.mitre.org/stix-1}"+ "STIX_Package"
                    try:
                        stix_object = parser.parse_xml(StringIO(unicode(etree.tostring(child))), check_version=False)
                        stix_namespaces = stix_object.__input_namespaces__
                        stix_json = json.loads(stix_object.to_json())
                        result_list.append((stix_json, stix_namespaces))
                        failed = False
                        del stix_object
                    except Exception as e:
                        self.stdout.write('Failed: %s' % (e))
                        continue
                # free xml root
                del root
                del tree
                del xml_content
            if failed:
                return []
        return result_list

    def check_file_or_directory(self, arglist):
        """check if arguemnt list contains directories and get files
        returns: list of files
        """
        file_list = []
        for item in arglist:
            if os.path.isfile(item):
                file_list.append(item)
            if os.path.isdir(item):
                for fn in os.listdir(item):
                    file_list.append(os.path.join(item, fn))
        return file_list

    def add_arguments(self, parser):
        """add path/file argument
        """
        parser.add_argument('stix_xml', nargs='+', type=str)

    def handle(self, *args, **options):
        """iterate over files in given xml path or direct file and extract stix information
        returns: nothing
        """
        if settings.ENABLE_BACKUP_STIX:
            if not os.path.exists(settings.MY_BACKUP_DIRECTORY):
                os.makedirs(settings.MY_BACKUP_DIRECTORY)
            # create daily subdirectory
            backup_dir = os.path.join(settings.MY_BACKUP_DIRECTORY, time.strftime('%Y-%m-%d'))
            if not os.path.exists(backup_dir):
                os.makedirs(backup_dir)
        parser = EntityParser()
        file_list = self.check_file_or_directory(options['stix_xml'])
        for xml in file_list:
            result_list = self.iterate_xml(xml, parser)
            for stix_json_index in xrange(len(result_list) - 1, -1, -1):
                stix_json_tuple = result_list[stix_json_index]
                stix_json = stix_json_tuple[0]
                self.stix_namespaces_dict = stix_json_tuple[1]
                # version check
                if not self.perform_version_check(stix_json):
                    # free stix json
                    del result_list[stix_json_index]
                    continue

                # extract package information
                package_object = self.perform_stix_header_extraction(stix_json)
                if 'stix_header' in stix_json:
                    stix_json.pop('stix_header')
                if package_object.produced_time and 'timestamp' in stix_json:
                    stix_json.pop('timestamp')
                elif not package_object.produced_time and 'timestamp' in stix_json:
                    package_object.produced_time = date_parser(stix_json['timestamp']).replace(tzinfo=pytz.UTC)
                    package_object.save()
                    stix_json.pop('timestamp')
                # extract observables
                if 'observables' in stix_json:
                    package_object = self.perform_observable_extraction(stix_json, package_object)
                    stix_json.pop('observables')
                # extract indicators
                if 'indicators' in stix_json:
                    package_object = self.perform_indicator_extraction(stix_json, package_object)
                    stix_json.pop('indicators')
                # extract campaigns
                if 'campaigns' in stix_json:
                    package_object = self.perform_campaign_extraction(stix_json, package_object)
                    stix_json.pop('campaigns')
                # extract threat actors
                if 'threat_actors' in stix_json:
                    package_object = self.perform_threat_actor_extraction(stix_json, package_object)
                    stix_json.pop('threat_actors')
                # extract ttps
                if 'ttps' in stix_json:
                    package_object = self.perform_ttp_extraction(stix_json, package_object)
                    stix_json.pop('ttps')

                package_object.save()
                #print json.dumps(stix_json, indent=4, sort_keys=True)

                # add missed base elements
                for element in stix_json.keys():
                    if element not in self.common_elements:
                        self.missed_elements['stix'][element] = True

                # iterate over missing references and check if database objects exist, remove those entries
                for item in self.missing_references:
                    if len(self.missing_references[item])>0:
                        if item == 'object_2_object':
                            for object_id in self.missing_references[item].keys():
                                try:
                                    for object_one_dict in self.id_mapping['objects'][object_id]:
                                        for object_two_id_item in list(self.missing_references[item][object_id]):
                                            try:
                                                for object_two_dict in self.id_mapping['objects'][object_two_id_item['id']]:
                                                    related_object, created = Related_Object.objects.get_or_create(
                                                        relationship = object_two_id_item['relationship'],
                                                        object_one_id = object_one_dict['object_id'],
                                                        object_one_type = object_one_dict['object_type'],
                                                        object_two_id = object_two_dict['object_id'],
                                                        object_two_type = object_two_dict['object_type']
                                                    )
                                            except KeyError as e:
                                                continue
                                            self.missing_references[item][object_id].remove(object_two_id_item)
                                except KeyError as e:
                                    continue
                                if len(self.missing_references[item][object_id]) == 0:
                                    del self.missing_references[item][object_id]
                        if item == 'email_2_attachment':
                            for object_id in self.missing_references[item].keys():
                                try:
                                    for email_object_dict in self.id_mapping['objects'][object_id]:
                                        email_object = self.get_database_object(**email_object_dict)
                                        for attachment_reference_index in xrange(len(self.missing_references[item][object_id])-1, -1, -1):
                                            attachment_reference_dict = self.missing_references[item][object_id][attachment_reference_index]
                                            if attachment_reference_dict['idref'] in self.id_mapping['objects']:
                                                for attachment_object_meta in self.id_mapping['objects'][attachment_reference_dict['idref']]:
                                                    attachment_object = self.get_database_object(attachment_object_meta['object_id'], attachment_object_meta['object_type'])
                                                    email_object.attachments.add(attachment_object)
                                                    del self.missing_references[item][object_id][attachment_reference_index]
                                                email_object.save()
                                    if len(self.missing_references[item][object_id])<=0:
                                        del self.missing_references[item][object_id]
                                except KeyError as e:
                                    continue
                        if item == 'actor_2_actor':
                            for object_id in self.missing_references[item].keys():
                                try:
                                    threat_actor_db_id = self.id_mapping['threat_actors'][object_id]
                                    threat_actor_object = ThreatActor.objects.get(id=threat_actor_db_id)
                                    for associated_actor_idref in list(self.missing_references[item][object_id]):
                                        try:
                                            associated_actor_db_id = self.id_mapping['threat_actors'][associated_actor_idref]
                                            associated_actor_object = ThreatActor.objects.get(id=associated_actor_db_id)
                                            threat_actor_object.associated_threat_actors.add(associated_actor_object)
                                            self.missing_references[item][object_id].remove(associated_actor_idref)
                                        except KeyError as e:
                                            try:
                                                associated_actor_object = ThreatActor.objects.get(threat_actor_id=associated_actor_idref)
                                                threat_actor_object.associated_threat_actors.add(associated_actor_object)
                                                self.missing_references[item][object_id].remove(associated_actor_idref)
                                            except ThreatActor.DoesNotExist:
                                                continue
                                    threat_actor_object.save()
                                    if len(self.missing_references[item][object_id])<=0:
                                        del self.missing_references[item][object_id]
                                except KeyError as e:
                                    print e
                                    continue
                        if item == 'actor_2_campaign':
                            for object_id in self.missing_references[item].keys():
                                try:
                                    threat_actor_db_id = self.id_mapping['threat_actors'][object_id]
                                    threat_actor_object = ThreatActor.objects.get(id=threat_actor_db_id)
                                    for associated_campaign_idref in list(self.missing_references[item][object_id]):
                                        try:
                                            associated_campaign_db_id = self.id_mapping['campaigns'][associated_campaign_idref]
                                            associated_campaign_object = Campaign.objects.get(id=associated_campaign_db_id)
                                            threat_actor_object.campaigns.add(associated_campaign_object)
                                            self.missing_references[item][object_id].remove(associated_campaign_idref)
                                        except KeyError as e:
                                            continue
                                    threat_actor_object.save()
                                    if len(self.missing_references[item][object_id])<=0:
                                        del self.missing_references[item][object_id]
                                except KeyError as e:
                                    continue
                        if item == 'indicator_2_indicator':
                            for object_id in self.missing_references[item].keys():
                                try:
                                    indicator_db_id = self.id_mapping['indicators'][object_id]
                                    indicator_object = Indicator.objects.get(id=indicator_db_id)
                                    for composite_indicator_idref in list(self.missing_references[item][object_id]):
                                        try:
                                            composite_indicator_db_id = self.id_mapping['indicators'][composite_indicator_idref]
                                            composite_indicator_object = Indicator.objects.get(id=composite_indicator_db_id)
                                            indicator_object.related_indicators.add(composite_indicator_object)
                                            self.missing_references[item][object_id].remove(composite_indicator_idref)
                                        except KeyError as e:
                                            try:
                                                composite_indicator_object = Indicator.objects.get(indicator_id=composite_indicator_idref)
                                                indicator_object.related_indicators.add(composite_indicator_object)
                                                self.missing_references[item][object_id].remove(composite_indicator_idref)
                                            except Indicator.DoesNotExist:
                                                continue
                                    indicator_object.save()
                                    if len(self.missing_references[item][object_id])<=0:
                                        del self.missing_references[item][object_id]
                                except KeyError as e:
                                    continue
                        if item == 'indicator_2_observable':
                            for object_id in self.missing_references[item].keys():
                                try:
                                    indicator_db_id = self.id_mapping['indicators'][object_id]
                                    indicator_object = Indicator.objects.get(id=indicator_db_id)
                                    observable_idref = self.missing_references[item][object_id]
                                    try:
                                        observable_db_id = self.id_mapping['observables'][observable_idref]
                                        observable_object = Observable.objects.get(id=observable_db_id)
                                        observable_object.indicators.add(indicator_object)
                                        observable_object.save()
                                        del self.missing_references[item][object_id]
                                    except KeyError as e:
                                        # create dummy observable with IDREF for later update
                                        obs_namespace_obj = self.get_full_namespace2(observable_idref.split(':', 1)[0])
                                        observable_dict = {
                                            'name': observable_idref,
                                            'description': 'No Description',
                                            'short_description': 'No Short Description',
                                            'observable_type': 'Dummy',
                                            'observable_id': observable_idref
                                        }
                                        observable_object, observable_created = Observable.objects.get_or_create(**observable_dict)
                                        observable_object.namespace.add(obs_namespace_obj)
                                        observable_object.indicators.add(indicator_object)
                                        observable_object.save()
                                except KeyError as e:
                                    continue
                        if item == 'composite_2_observable':
                            for object_id in self.missing_references[item].keys():
                                try:
                                    comp_db_id = self.id_mapping['compositions'][object_id]
                                    comp_object = ObservableComposition.objects.get(id=comp_db_id)
                                    for observable_idref in list(self.missing_references[item][object_id]):
                                        try:
                                            observable_db_id = self.id_mapping['observables'][observable_idref]
                                            observable_object = Observable.objects.get(id=observable_db_id)
                                            comp_object.observables.add(observable_object)
                                            self.missing_references[item][object_id].remove(observable_idref)
                                        except KeyError as e:
                                            try:
                                                observable_object = Observable.objects.get(observable_id=observable_idref)
                                                comp_object.observables.add(observable_object)
                                                self.missing_references[item][object_id].remove(observable_idref)
                                            except Observable.DoesNotExist:
                                                # TODO: create dummy observable?
                                                continue
                                    comp_object.save()
                                    if len(self.missing_references[item][object_id])<=0:
                                        del self.missing_references[item][object_id]
                                except KeyError as e:
                                    continue
                        if item == 'ttp_2_ttp':
                            for object_id in self.missing_references[item].keys():
                                try:
                                    ttp_db_id = self.id_mapping['ttps'][object_id]
                                    ttp_object = TTP.objects.get(id=ttp_db_id)
                                    for related_ttp_idref, related_ttp_relationship in list(self.missing_references[item][object_id]):
                                        try:
                                            related_ttp_db_id = self.id_mapping['ttps'][related_ttp_idref]
                                            related_ttp_object = TTP.objects.get(id=related_ttp_db_id)
                                            ttp_object.add_related_ttp(related_ttp_object, related_ttp_relationship)
                                            ttp_object.save()
                                            self.missing_references[item][object_id].remove((related_ttp_idref, related_ttp_relationship))
                                        except KeyError as e:
                                            continue
                                    ttp_object.save()
                                    if len(self.missing_references[item][object_id])<=0:
                                        del self.missing_references[item][object_id]
                                except KeyError as e:
                                    continue
                        if item == 'campaign_2_ttp':
                            for object_id in self.missing_references[item].keys():
                                try:
                                    campaign_db_id = self.id_mapping['campaigns'][object_id]
                                    campaign_object = Campaign.objects.get(id=campaign_db_id)
                                    for related_ttp_idref, related_ttp_relationship in list(self.missing_references[item][object_id]):
                                        try:
                                            related_ttp_db_id = self.id_mapping['ttps'][related_ttp_idref]
                                            related_ttp_object = TTP.objects.get(id=related_ttp_db_id)
                                            campaign_object.add_related_ttp(related_ttp_object, related_ttp_relationship)
                                            campaign_object.save()
                                            self.missing_references[item][object_id].remove((related_ttp_idref, related_ttp_relationship))
                                        except KeyError as e:
                                            continue
                                    campaign_object.save()
                                    if len(self.missing_references[item][object_id])<=0:
                                        del self.missing_references[item][object_id]
                                except KeyError as e:
                                    continue
                        if item == 'actor_2_ttp':
                            for object_id in self.missing_references[item].keys():
                                try:
                                    actor_db_id = self.id_mapping['threat_actors'][object_id]
                                    actor_object = ThreatActor.objects.get(id=actor_db_id)
                                    for observed_ttp_idref, observed_ttp_relationship in list(self.missing_references[item][object_id]):
                                        try:
                                            observed_ttp_db_id = self.id_mapping['ttps'][observed_ttp_idref]
                                            observed_ttp_object = TTP.objects.get(id=observed_ttp_db_id)
                                            actor_object.add_observed_ttp(observed_ttp_object, observed_ttp_relationship)
                                            actor_object.save()
                                            self.missing_references[item][object_id].remove((observed_ttp_idref, observed_ttp_relationship))
                                        except KeyError as e:
                                            continue
                                    actor_object.save()
                                    if len(self.missing_references[item][object_id])<=0:
                                        del self.missing_references[item][object_id]
                                except KeyError as e:
                                    continue
                        if item == 'indicator_2_ttp':
                            for object_id in self.missing_references[item].keys():
                                try:
                                    indicator_db_id = self.id_mapping['indicators'][object_id]
                                    indicator_object = Indicator.objects.get(id=indicator_db_id)
                                    for ttp_idref in list(self.missing_references[item][object_id]):
                                        try:
                                            ttp_db_id = self.id_mapping['ttps'][ttp_idref]
                                            ttp_object = TTP.objects.get(id=ttp_db_id)
                                            indicator_object.ttps.add(ttp_object)
                                            indicator_object.save()
                                            self.missing_references[item][object_id].remove(ttp_idref)
                                        except KeyError as e:
                                            try:
                                                ttp_object = TTP.objects.get(ttp_id=ttp_idref)
                                                indicator_object.ttps.add(ttp_object)
                                                self.missing_references[item][object_id].remove(ttp_idref)
                                            except TTP.DoesNotExist:
                                                # TODO: create dummy ttp ?
                                                continue
                                    indicator_object.save()
                                    if len(self.missing_references[item][object_id])<=0:
                                        del self.missing_references[item][object_id]
                                except KeyError as e:
                                    continue
                # free stix json
                del result_list[stix_json_index]
                if settings.ENABLE_BACKUP_STIX:
                    # move file to backup location
                    try:
                        shutil.move(xml, backup_dir)
                    except Exception as e:
                        print("failed moving file to backup directory: %s" % (e))
                if settings.DELETE_IMPORTED_STIX:
                    try:
                        os.remove(xml)
                    except Exception as e:
                        print("failed removing stix xml file: %s" % (e))
        self.stdout.write('------')
        # print all missing object references
        for item in self.missing_references:
            if len(self.missing_references[item])>0:
                    self.stdout.write('Missing references for: %s' % (item))
                    for entry in self.missing_references[item]:
                        self.stdout.write("%s -> %s " % (entry, self.missing_references[item][entry]))
        self.stdout.write('------')
        # print missing elements
        for element_type in self.missed_elements:
            if len(self.missed_elements[element_type])>0:
                self.stdout.write("Missing %s elements:" % (element_type))
                for item in self.missed_elements[element_type]:
                    self.stdout.write("Missing %s element implementation: %s" % (element_type, item))
        self.stdout.write('------')
        # print missing object types
        if len(self.missed_objects)>0:
            self.stdout.write("Missing Object Types:")
            for item in self.missed_objects:
                self.stdout.write("Missing object type implementation: %s" % (item))
        self.stdout.write('------')
        return
