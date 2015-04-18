# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.db.models import Prefetch, Q
from django.contrib import messages
from django.shortcuts import render_to_response
from django.template import RequestContext

from kraut_parser.models import Package, Observable, Related_Object, Indicator, Campaign
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

def campaign(request, campaign_id="1"):
    context = {'campaign_id': campaign_id, 'campaign': None}
    try:
        campaign = Campaign.objects.filter(pk=int(campaign_id)).prefetch_related(
            Prefetch('confidence'),
            Prefetch('related_indicators'),
            Prefetch('associated_campaigns'),
        )
    except Campaign.DoesNotExist:
        messages.error(request, 'The requested campaign does not exist!')
        return render_to_response('kraut_intel/campaign_details.html', context, context_instance=RequestContext(request))
    if len(campaign)<=0:
        messages.warning(request, "No campaign with the given ID exists in the system.")
    else:
        context['campaign'] = campaign[0]
        context['namespace_icon'] = get_icon_for_namespace(campaign[0].namespace)
        try:
            context['confidence'] = campaign[0].confidence.last().value
            context['num_indicators'] = campaign[0].related_indicators.count()
            context['num_campaigns'] = campaign[0].associated_campaigns.count()
            context['tab'] = 'indicators'
            if context['confidence'] == 'Low':
                context['confidence_color'] = 'success'
            elif context['confidence'] == 'Medium':
                context['confidence_color'] = 'warning'
            else:
                context['confidence_color'] = 'danger'
        except:
            context['confidence'] = 'Low'
            context['confidence_color'] = 'success'
    return render_to_response('kraut_intel/campaign_details.html', context, context_instance=RequestContext(request))

def indicators(request):
    context = {}
    return render_to_response('kraut_intel/indicators.html', context, context_instance=RequestContext(request))

def indicator(request, indicator_id="1"):
    """ details of a single indicator
    """
    context = {'indicator_id': indicator_id, 'indicator': None, 'tab': 'indicators'}
    try:
        indicator = Indicator.objects.filter(pk=int(indicator_id)).prefetch_related(
            Prefetch('indicator_types'),
            Prefetch('confidence'),
            Prefetch('related_indicators'),
            Prefetch('observablecomposition_set')
        )
    except Indicator.DoesNotExist:
        messages.error(request, "The requested indicator does not exist!")
        return render_to_response('kraut_intel/indicator_details.html', context, context_instance=RequestContext(request))
    if len(indicator)<=0:
        messages.warning(request, "No indicator with the given ID exists in the system.")
    else:
        context['indicator'] = indicator[0]
        context['namespace_icon'] = get_icon_for_namespace(indicator[0].namespace)
        context['num_indicators'] = indicator[0].related_indicators.count()
        context['num_observables'] = indicator[0].observable_set.count()
        context['num_observable_compositions'] = indicator[0].observablecomposition_set.count()
        if context['num_indicators'] > 0:
            context['tab'] = 'indicators'
        elif context['num_observables'] > 0:
            context['tab'] = 'observables'
        elif context['num_observable_compositions'] > 0:
            context['tab'] = 'compositions'
        context['confidence'] = indicator[0].confidence.last().value
        if context['confidence'] == 'Low':
            context['confidence_color'] = 'success'
        elif context['confidence'] == 'Medium':
            context['confidence_color'] = 'warning'
        else:
            context['confidence_color'] = 'danger'
        ### TODO: currently supports only single composition in indicator
        if context['num_observable_compositions'] > 0:
            for composition in indicator[0].observablecomposition_set.all():
                context['composition_id'] = composition.id
        else:
            context['composition_id'] = None
    return render_to_response('kraut_intel/indicator_details.html', context, context_instance=RequestContext(request))

def observables(request):
    context = {}
    return render_to_response('kraut_intel/observables.html', context, context_instance=RequestContext(request))

def observable(request, observable_id="1"):
    """ details of a single observable
    """
    context = {'observable_id': observable_id, 'observable': None, 'objects': None, 'related_objects': [], 'related_observables': []}
    try:
        observable = Observable.objects.filter(pk=int(observable_id)).prefetch_related(
            Prefetch('indicators'),
        )
    except Observable.DoesNotExist:
        messages.error(request, 'The requested observable does not exist!')
        return render_to_response('kraut_intel/observable_details.html', context, context_instance=RequestContext(request))
    if len(observable)<=0:
        messages.warning(request, "No observable with the given ID exists in the system.")
    else:
        context['observable'] = observable[0]
        context['namespace_icon'] = get_icon_for_namespace(observable[0].namespace)
        context['objects'] = get_object_for_observable(observable[0].observable_type, observable[0])
        # get related objects
        for obj in context['objects']:
            context['related_objects'].append(get_related_objects_for_object(obj.id, observable[0].observable_type))
            context['related_observables'].append(obj.observables.all())
        # check object type specific settings
        if observable[0].observable_type == 'FileObjectType':
            context['custom'] = []
            context['meta'] = []
            context['hashes'] = []
            context['active_tab'] = 'hashes'
            for obj in context['objects']:
                for custom in obj.file_custom.all():
                    context['custom'].append({'name': custom.property_name, 'value': custom.property_value})
                    context['active_tab'] = 'custom'
                for meta in obj.file_meta.all():
                    if meta.file_name != 'No Name' or meta.file_path != 'No Path' or meta.file_extension != 'No Extension' or meta.file_size != 0:
                        context['meta'].append({
                                'name': meta.file_name,
                                'path': meta.file_path,
                                'extension': meta.file_extension,
                                'size': meta.file_size
                            })
                        context['active_tab'] = 'meta'
                if obj.md5_hash != 'No MD5' or obj.sha256_hash != 'No SHA256':
                    context['hashes'] = True
                    context['active_tab'] = 'hashes'
    return render_to_response('kraut_intel/observable_details.html', context, context_instance=RequestContext(request))
