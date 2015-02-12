# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

import django_filters

from kraut_parser.models import Package

class PackageFilter(django_filters.FilterSet):
    name = django_filters.CharFilter(lookup_type='icontains', label='Package Name')
    last_modified = django_filters.CharFilter(lookup_type='contains', label='YYYY-MM-DD')

    class Meta:
        model = Package
        fields = ['name', 'last_modified', 'namespace']
