# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.shortcuts import render_to_response
from django.template import RequestContext
from django_tables2 import RequestConfig
from kraut_intel.tables import PackageTable
from kraut_intel.filters import PackageFilter
from kraut_parser.models import Package

# Create your views here.

def home(request):
    context = {}
    return render_to_response('kraut_intel/index.html', context, context_instance=RequestContext(request))

def packages(request):
    packages_filter = PackageFilter(request.GET, queryset=Package.objects.all())
    packages = PackageTable(packages_filter.qs)
    RequestConfig(request, paginate={"per_page": 10}).configure(packages)
    context = {'packages': packages, 'filter': packages_filter}
    return render_to_response('kraut_intel/packages.html', context, context_instance=RequestContext(request))

def threatactors(request):
    context = {}
    return render_to_response('kraut_intel/threatactors.html', context, context_instance=RequestContext(request))
