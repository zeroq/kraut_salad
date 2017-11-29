# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

import requests, csv, uuid, re, hashlib

from dateutil.parser import parse

from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from django.db.models import Count
from django.utils import timezone

# import database models
from kraut_sharing.models import OSINT_Feed
from kraut_parser.models import Indicator, Package, Namespace, Indicator_Type, Indicator_Kill_Chain_Phase, Confidence, Address_Object, Observable

class Command(BaseCommand):
    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)

    def create_package(self, ptitle, description, short_description, source, namespace, ptime, version="1.1.1"):
        """create STIX package stuff
        """
        title_hash = hashlib.md5(ptitle).hexdigest()
        package_id = uuid.uuid3(uuid.NAMESPACE_DNS, title_hash)
        ns_obj, ns_created = Namespace.objects.get_or_create(namespace="%s" % (namespace))
        package_dict = {
            'package_id': str(package_id),
            'version': version,
            'name': ptitle,
            'description': description,
            'short_description': short_description,
            'source': source,
            'produced_time': timezone.make_aware(parse(ptime), timezone.get_current_timezone()),
        }
        package_object, package_object_created = Package.objects.get_or_create(**package_dict)
        package_object.namespace.add(ns_obj)
        package_object.save()
        return package_object, ns_obj

    def create_indicator(self, title, description, ns_obj):
        """create STIX indicator
        """
        title_hash = hashlib.md5(title).hexdigest()
        indicator_id = uuid.uuid3(uuid.NAMESPACE_DNS, title_hash)
        indicator_dict = {
            'name': title,
            'description': description,
            'short_description': 'No Short Description',
            'indicator_id': indicator_id
        }
        indicator_object, indicator_object_created = Indicator.objects.get_or_create(**indicator_dict)
        # add namespace
        indicator_object.namespace.add(ns_obj)
        # add confidence
        confidence_object, confidence_created = Confidence.objects.get_or_create(**{'value': 'Low', 'description': 'No Description'})
        indicator_object.confidence.add(confidence_object)
        # add indicator type
        indicator_type_object, indicator_type_created = Indicator_Type.objects.get_or_create(itype="C2")
        indicator_object.indicator_types.add(indicator_type_object)
        # add kill chain phase
        kcp_object, kcp_created = Indicator_Kill_Chain_Phase.objects.get_or_create(**{'name': 'Command and Control', 'ordinality': 6})
        indicator_object.kill_chain_phases.add(kcp_object)
        indicator_object.save()
        return indicator_object

    def handle_bambenek_ip(self, feed, malware_types):
        """create packages for each malware type
        """
        for mwtype in malware_types:
            ptitle = "%s - %s" % (mwtype, malware_types[mwtype][0][2].split(' ', 1)[0])
            print(ptitle)
            pobj, nsobj = self.create_package(ptitle, malware_types[mwtype][0][1], mwtype, "OSINT", feed.namespace, malware_types[mwtype][0][2])
            iobj = self.create_indicator("Indicator for %s" % (mwtype), mwtype, nsobj)
            pobj.indicators.add(iobj)
            for row in malware_types[mwtype]:
                # ['193.218.145.50', 'IP used by vawtrak C&C', '2017-07-11 20:13', 'http://osint.bambenekconsulting.com/manual/vawtrak.txt']
                aobj, acreated = Address_Object.objects.get_or_create(**{'address_value': row[0], 'category': 'ipv4-addr', 'condition': 'equals'})
                oname_hash = hashlib.md5('IP: %s' % (row[0])).hexdigest()
                obs_id = uuid.uuid3(uuid.NAMESPACE_DNS, oname_hash)
                oobj, ocreated = Observable.objects.get_or_create(**{'name': 'IP: %s' % (row[0]), 'observable_type': 'AddressObjectType', 'observable_id': obs_id})
                oobj.namespace.add(nsobj)
                oobj.indicators.add(iobj)
                oobj.save()
                aobj.observables.add(oobj)
                aobj.save()
                #pass
                #print(row)
            pobj.save()
            #break


    def handle(self, *args, **options):
        type_re = re.compile('IP used by (.*?)$')
        feeds = OSINT_Feed.objects.all()
        for feed in feeds.iterator():
            self.stdout.write('- Checking feed: %s (%s)' % (feed.name, feed.last_pull))
            rsp = requests.get(feed.url)
            text = rsp.iter_lines()
            reader = csv.reader(text, delimiter=',')
            malware_types = {}
            for row in reader:
                if row[0].startswith('#') or len(row)!=4:
                    continue
                # parse csv row according to feed source
                if feed.source == 'bambenek_ip':
                    # ['193.218.145.50', 'IP used by vawtrak C&C', '2017-07-11 20:13', 'http://osint.bambenekconsulting.com/manual/vawtrak.txt']
                    short_description = row[1]
                    match = type_re.search(row[1])
                    if match:
                        mwtype = match.groups()[0]
                    else:
                        mwtype = 'unknown C&C'
                    try:
                        malware_types[mwtype].append(row)
                    except:
                        malware_types[mwtype] = [row]
            # check feed source and handle accordingly
            if feed.source == 'bambenek_ip':
                self.handle_bambenek_ip(feed, malware_types)
