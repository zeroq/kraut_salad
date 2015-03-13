# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.db.models import Prefetch
from django.contrib import messages
from django.shortcuts import render_to_response
from django.template import RequestContext
from kraut_parser.models import Package

# Create your views here.

def home(request):
    context = {}
    return render_to_response('kraut_intel/index.html', context, context_instance=RequestContext(request))

def packages(request):
    context = {}
    return render_to_response('kraut_intel/packages.html', context, context_instance=RequestContext(request))

def package(request, package_id="1"):
    context = {'package_id': package_id, 'package': None}
    try:
        package = Package.objects.filter(id=int(package_id)).prefetch_related(
                    Prefetch('threat_actors'),
                    Prefetch('campaigns'),
                    Prefetch('indicators'),
                    Prefetch('observables'),
                )
    except Package.DoesNotExist:
        messages.error(request, 'The requested package does not exist!')
        return render_to_response('kraut_intel/package_details.html', context, context_instance=RequestContext(request))
    if len(package)<=0:
        messages.warning(request, "No package with the given ID exists in the system.")
    else:
        context['package'] = package[0]
    return render_to_response('kraut_intel/package_details.html', context, context_instance=RequestContext(request))

def threatactors(request):
    context = {}
    return render_to_response('kraut_intel/threatactors.html', context, context_instance=RequestContext(request))

def observables(request):
    context = {}
    return render_to_response('kraut_intel/observables.html', context, context_instance=RequestContext(request))

