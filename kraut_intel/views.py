# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.db.models import Prefetch, Q
from django.contrib import messages
from django.shortcuts import render_to_response
from django.template import RequestContext

from kraut_parser.models import Package, Observable, Related_Object
from kraut_parser.utils import get_object_for_observable, get_related_objects_for_object

from kraut_intel.utils import get_icon_for_namespace

# Create your views here.

def home(request):
    context = {}
    return render_to_response('kraut_intel/index.html', context, context_instance=RequestContext(request))

def packages(request):
    """ list all intelligence packages
    """
    context = {}
    return render_to_response('kraut_intel/packages.html', context, context_instance=RequestContext(request))

def package(request, package_id="1"):
    """ details of a single intelligence package
    """
    context = {'package_id': package_id, 'package': None}
    try:
        package = Package.objects.filter(pk=int(package_id)).prefetch_related(
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
        context['namespace_icon'] = get_icon_for_namespace(package[0].namespace)
        context['num_threat_actors'] = package[0].threat_actors.count()
        context['num_campaigns'] = package[0].campaigns.count()
        context['num_indicators'] = package[0].indicators.count()
        context['num_observables'] = package[0].observables.count()
        if context['num_threat_actors'] > 0:
            context['tab'] = 'threatactors'
        elif context['num_campaigns'] > 0:
            context['tab'] = 'campaigns'
        elif context['num_indicators'] > 0:
            context['tab'] = 'indicators'
        else:
            context['tab'] = 'observables'
        context['quick_pane'] = {}
        for obs_obj in package[0].observables.all():
            context['quick_pane'][obs_obj.observable_type] = True
    return render_to_response('kraut_intel/package_details.html', context, context_instance=RequestContext(request))

def threatactors(request):
    context = {}
    return render_to_response('kraut_intel/threatactors.html', context, context_instance=RequestContext(request))

def campaigns(request):
    context = {}
    return render_to_response('kraut_intel/campaigns.html', context, context_instance=RequestContext(request))

def indicators(request):
    context = {}
    return render_to_response('kraut_intel/indicators.html', context, context_instance=RequestContext(request))

def observables(request):
    context = {}
    return render_to_response('kraut_intel/observables.html', context, context_instance=RequestContext(request))

def observable(request, observable_id="1"):
    """ details of a single observable
    """
    context = {'observable_id': observable_id, 'observable': None, 'objects': None, 'related_objects': []}
    try:
        observable = Observable.objects.filter(pk=int(observable_id)).prefetch_related(
            Prefetch('indicators'),
        )
    except Observable.DoesNotExist:
        messages.error(request, 'The requested observable does not exist!')
        return render_to_response('kraut_intel/observable_details.html', context, context_instance=RequestContext(request))
    if len(observable)<=0:
        messages.warning(request, "No package with the given ID exists in the system.")
    else:
        context['observable'] = observable[0]
        context['namespace_icon'] = get_icon_for_namespace(observable[0].namespace)
        context['objects'] = get_object_for_observable(observable[0].observable_type, observable[0])
        # get related objects
        for obj in context['objects']:
            context['related_objects'].append(get_related_objects_for_object(obj.id, observable[0].observable_type))
    return render_to_response('kraut_intel/observable_details.html', context, context_instance=RequestContext(request))
