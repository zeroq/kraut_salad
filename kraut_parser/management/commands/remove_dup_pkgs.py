# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.core.management.base import BaseCommand, CommandError
from django.conf import settings
from django.db.models import Count
# import database models
from kraut_parser.models import Package

class Command(BaseCommand):
    def __init__(self, *args, **kwargs):
        super(Command, self).__init__(*args, **kwargs)

    def handle(self, *args, **options):
        p = Package.objects.filter(package_id='edge:Package-a7b3f172-5204-473f-b77d-bce34d071611')
        print(p.count())
        self.stdout.write('------')
        pkgs = Package.objects.values('package_id').annotate(tcount=Count('package_id')).order_by('-tcount')
        for p in pkgs:
            if p['tcount'] > 1:
                print("Name: %s Count: %s" % (p['package_id'], p['tcount']))
                k = Package.objects.filter(package_id=p['package_id'])
                for index in range(0, p['tcount']-1):
                    k[0].delete()
        return
