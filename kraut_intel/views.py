# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.shortcuts import render_to_response
from django.template import RequestContext

from kraut_parser.models import Package

# Create your views here.

def home(request):
    context = {}
    return render_to_response('kraut_intel/index.html', context, context_instance=RequestContext(request))

def packages(request):
    packages = Package.objects.all()
    context = {
        'packages': packages,
    }

    return render_to_response('kraut_intel/packages.html', context, context_instance=RequestContext(request))

def threatactors(request):
    context = {}
    return render_to_response('kraut_intel/threatactors.html', context, context_instance=RequestContext(request))
