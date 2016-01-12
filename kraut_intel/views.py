# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.http import HttpResponseRedirect
from django.db.models import Prefetch, Q
from django.contrib import messages
from django.shortcuts import render_to_response
from django.core.urlresolvers import reverse
from django.template import RequestContext
from django.utils.html import strip_tags
from django.contrib.auth.decorators import login_required

from kraut_parser.models import Package, Observable, Related_Object, Indicator, Campaign, ThreatActor, TA_Types, TA_Roles, TA_Alias, TTP, MalwareInstance
from kraut_parser.models import AttackPattern, Namespace
from kraut_parser.utils import get_object_for_observable, get_related_objects_for_object

from kraut_intel.utils import get_icon_for_namespace
from kraut_intel.forms import PackageForm

import datetime, uuid, argparse

# Create your views here.

@login_required
def home(request):
    context = {}
    return render_to_response('kraut_intel/index.html', context, context_instance=RequestContext(request))

@login_required
def packages(request):
    """ list all intelligence packages
    """
    context = {}
    return render_to_response('kraut_intel/packages.html', context, context_instance=RequestContext(request))

@login_required
def delete_package(request, package_id="1"):
    """ delete intelligence package with given ID
    """
    try:
        package = Package.objects.get(pk=int(package_id))
    except Package.DoesNotExist:
        messages.error(request, 'The requested package does not exist!')
        return render_to_response('kraut_intel/packages.html', {}, context_instance=RequestContext(request))
    ### iterate over observables/objects and delete
    for ob in package.observables.all():
        ### TODO: check for unneeded objects
        ob.delete()
    ### iterate over indicators
    for ic in package.indicators.all():
        ic.delete()
    ### iterate over campaigns
    for ca in package.campaigns.all():
        ca.delete()
    ### iterate over threat actors
    for ta in package.threat_actors.all():
        ta.delete()
    # delete package
    package.delete()
    messages.info(request, 'The intelligence package was deleted successfully!')
    return HttpResponseRedirect(reverse('intel:packages'))

@login_required
def edit_create_package(request, package_id=None):
    """ create a new intel package or edit an existing one
    """
    context = {}
    if request.method == 'POST':
        form = PackageForm(request.POST)
        if form.is_valid():
            ### TODO: make modifications or create new package
            if int(package_id) == 0:
                messages.info(request, 'New Package Created!')
            else:
                messages.info(request, 'Package Updated! (%s)' % (package_id))
            return HttpResponseRedirect(reverse('intel:packages'))
        messages.error(request, 'Package not valid!')
        return HttpResponseRedirect(reverse('intel:edit_create_package', kwargs={'package_id': package_id}))
    else:
        if int(package_id)>0:
            try:
                package = Package.objects.get(pk=int(package_id))
            except Package.DoesNotExist:
                messages.error(request, 'The requested package does not exist!')
                return render_to_response('kraut_intel/packages.html', {}, context_instance=RequestContext(request))
        else:
            package = None
        if package:
            defaults = {
                'name': package.name,
                'produced_time': package.produced_time,
                'version': package.version,
                'source': package.source,
                'description': package.description,
                'package_id': package.package_id,
                'short_description': package.short_description
            }
            defaults['namespace'] = [b.pk for b in package.namespace.all()]
            form = PackageForm(defaults, instance=package)
        else:
            package_dict = {'name': 'Create New Intelligence Package'}
            package = argparse.Namespace(**package_dict)
            defaults = {
                'produced_time': datetime.datetime.now(),
                'package_id': 'nospace:package-%s' % (uuid.uuid4()),
            }
            form = PackageForm(defaults)
        context['form'] = form
        context['package_id'] = package_id
        context['package'] = package
    return render_to_response('kraut_intel/edit_create_package.html', context, context_instance=RequestContext(request))

@login_required
def update_package_header(request, package_id="1"):
    """ update header information of given package
    """
    try:
        package = Package.objects.get(pk=int(package_id))
    except Package.DoesNotExist:
        messages.error(request, 'The requested package does not exist!')
        return render_to_response('kraut_intel/packages.html', {}, context_instance=RequestContext(request))
    if request.method == "POST":
        pg_name = request.POST.get('package_name', None)
        pg_source = request.POST.get('package_source', None)
        pg_ns = request.POST.get('package_namespace', None)
        pg_descr = request.POST.get('package_description', None)
        if pg_name:
            package.name = pg_name
        if pg_source:
            package.source = pg_source
        if pg_ns:
            pg_obj, pg_created = Namespace.objects.get_or_create(namespace=pg_ns)
            package.namespace.clear()
            package.namespace.add(pg_obj)
        if pg_descr:
            package.description = pg_descr
        package.save()
    return HttpResponseRedirect(reverse("intel:package", kwargs={'package_id': package_id}))

@login_required
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
        context['description'] = ' '.join(package[0].description.strip().split())
        context['namespaces'] = Namespace.objects.all()
        context['namespace_icon'] = get_icon_for_namespace(package[0].namespace.last().namespace)
        context['num_threat_actors'] = package[0].threat_actors.count()
        context['num_campaigns'] = package[0].campaigns.count()
        context['num_ttps'] = package[0].ttps.count()
        context['num_indicators'] = package[0].indicators.count()
        context['num_observables'] = package[0].observables.count()
        if context['num_threat_actors'] > 0:
            context['tab'] = 'threatactors'
        elif context['num_campaigns'] > 0:
            context['tab'] = 'campaigns'
        elif context['num_indicators'] > 0:
            context['tab'] = 'indicators'
        elif context['num_ttps'] > 0:
            context['tab'] = 'ttps'
        else:
            context['tab'] = 'observables'
        context['quick_pane'] = {}
        for obs_obj in package[0].observables.all():
            context['quick_pane'][obs_obj.observable_type] = True
    return render_to_response('kraut_intel/package_details.html', context, context_instance=RequestContext(request))

@login_required
def package_graph(request, package_id="1"):
    """ show full tree graph for package
    """
    context = {'package_id': package_id, 'package': None}
    try:
        package = Package.objects.get(pk=int(package_id))
    except Package.DoesNotExist:
        messages.error(request, 'The requested package does not exist!')
        return render_to_response('kraut_intel/package_details.html', context, context_instance=RequestContext(request))
    context['package'] = package
    return render_to_response('kraut_intel/package_full_tree.html', context, context_instance=RequestContext(request))

@login_required
def threatactors(request):
    context = {}
    return render_to_response('kraut_intel/threatactors.html', context, context_instance=RequestContext(request))

@login_required
def delete_threatactor(request, threat_actor_id="1"):
    try:
        ta = ThreatActor.objects.get(pk=int(threat_actor_id))
    except ThreatAcotr.DoesNotExist:
        messages.error(request, 'The requested threat actor does not exist!')
        return render_to_response('kraut_intel/threatactors.html', {}, context_instance=RequestContext(request))
    ### TODO: check campaigns, ttps
    # delete threat actor
    ta.delete()
    messages.info(request, 'The threat actor was deleted successfully!')
    return HttpResponseRedirect(reverse('intel:threatactors'))

@login_required
def threatactor(request, threat_actor_id="1"):
    context = {'ta_id': threat_actor_id, 'ta': None}
    try:
        ta = ThreatActor.objects.filter(pk=int(threat_actor_id)).prefetch_related(
            Prefetch('campaigns'),
            Prefetch('associated_threat_actors'),
            Prefetch('observed_ttps'),
        )
    except ThreatActor.DoesNotExist:
        messages.error(request, 'The requested threat actor does not exist!')
        return render_to_response('kraut_intel/campaign_details.html', context, context_instance=RequestContext(request))
    if len(ta)<=0:
        messages.warning(request, "No threat actor with the given ID exists in the system.")
    else:
        context['ta'] = ta[0]
        try:
            ta_type_object = TA_Types.objects.get(actor=ta[0])
            ta_type = ta_type_object.ta_type
        except TA_Types.DoesNotExist:
            ta_type = "Unknown"
        try:
            ta_roles = TA_Roles.objects.filter(actor=ta[0])
        except TA_Roles.DoesNotExist:
            ta_roles = [{'role': "Unknown"}]
        ta_roles_string = ""
        for item in ta_roles:
            ta_roles_string += '%s, ' % (item.role)
        ta_roles_string = ta_roles_string.strip()[:-1]
        if ta_roles_string == "":
            ta_roles_string = "Unknown"
        try:
            ta_alias = TA_Alias.objects.filter(actor=ta[0])
        except TA_Alias.DoesNotExist:
            ta_alias = None
        context['ta_type'] = ta_type
        context['ta_roles'] = ta_roles_string
        context['ta_alias'] = ta_alias
        context['namespace_icon'] = get_icon_for_namespace(ta[0].namespace)
        context['tab'] = 'campaigns'
        context['num_campaigns'] = ta[0].campaigns.count()
        context['num_assoc_ta'] = ta[0].associated_threat_actors.count()
        context['num_ttps'] = ta[0].observed_ttps.count()
    return render_to_response('kraut_intel/threatactor_details.html', context, context_instance=RequestContext(request))

@login_required
def campaigns(request):
    context = {}
    return render_to_response('kraut_intel/campaigns.html', context, context_instance=RequestContext(request))

@login_required
def campaign(request, campaign_id="1"):
    context = {'campaign_id': campaign_id, 'campaign': None}
    try:
        campaign = Campaign.objects.filter(pk=int(campaign_id)).prefetch_related(
            Prefetch('confidence'),
            Prefetch('related_indicators'),
            Prefetch('associated_campaigns'),
            Prefetch('related_ttps'),
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
        except:
            context['confidence'] = 'Low'
            context['confidence_color'] = 'success'
        context['num_indicators'] = campaign[0].related_indicators.count()
        context['num_campaigns'] = campaign[0].associated_campaigns.count()
        context['num_ttps'] = campaign[0].related_ttps.count()
        if context['num_indicators'] >0:
            context['tab'] = 'indicators'
        elif context['num_campaigns']:
            context['tab'] = 'campaigns'
        else:
            context['tab'] = 'ttps'
        if context['confidence'] == 'Low':
            context['confidence_color'] = 'success'
        elif context['confidence'] == 'Medium':
            context['confidence_color'] = 'warning'
        else:
            context['confidence_color'] = 'danger'
    return render_to_response('kraut_intel/campaign_details.html', context, context_instance=RequestContext(request))

@login_required
def ttps(request):
    context = {}
    return render_to_response('kraut_intel/ttps.html', context, context_instance=RequestContext(request))

@login_required
def ttp(request, ttp_id="1"):
    context = {'ttp_id': ttp_id, 'ttp': None}
    try:
        ttp = TTP.objects.filter(pk=int(ttp_id)).prefetch_related(
            Prefetch('related_ttps'),
        )
    except TTP.DoesNotExist:
        messages.error(request, 'The requested TTP does not exist!')
        return render_to_response('kraut_intel/ttp_details.html', context, context_instance=RequestContext(request))
    if len(ttp)<=0:
        messages.error(request, 'No TTP with given ID exists in the system.')
    else:
        context['ttp'] = ttp[0]
        context['namespace_icon'] = get_icon_for_namespace(ttp[0].namespace)
        context['num_rel_ttps'] = ttp[0].related_ttps.count()
        context['num_instances'] = MalwareInstance.objects.filter(ttp_ref=ttp[0]).count()
        context['num_patterns'] = AttackPattern.objects.filter(ttp_ref=ttp[0]).count()
        if context['num_instances'] > 0:
            context['tab'] = 'malware_instances'
        else:
            context['tab'] = 'attack_patterns'
    return render_to_response('kraut_intel/ttp_details.html', context, context_instance=RequestContext(request))

@login_required
def indicators(request):
    context = {}
    return render_to_response('kraut_intel/indicators.html', context, context_instance=RequestContext(request))

@login_required
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

@login_required
def observables(request):
    context = {}
    return render_to_response('kraut_intel/observables.html', context, context_instance=RequestContext(request))

@login_required
def update_observable_header(request, observable_id="1"):
    """ update observable header information
    """
    try:
        observable = Observable.objects.get(pk=int(observable_id))
    except Observable.DoesNotExist:
        messages.error(request, 'The requested observable does not exist!')
        return render_to_response('kraut_intel/observables.html', {}, context_instance=RequestContext(request))
    if request.method == "POST":
        ob_name = request.POST.get('observable_name', None)
        ob_namespace = request.POST.get('observable_namespace', None)
        ob_description = request.POST.get('observable_description', None)
        if ob_name:
            observable.name = ob_name
        if ob_namespace:
            ob_obj, ob_created = Namespace.objects.get_or_create(namespace=ob_namespace)
            observable.namespace.clear()
            observable.namespace.add(ob_obj)
        if ob_description:
            observable.description = ob_description
        observable.save()
    return HttpResponseRedirect(reverse("intel:observable", kwargs={'observable_id': observable_id}))

@login_required
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
        context['namespace_icon'] = get_icon_for_namespace(observable[0].namespace.last().namespace)
        context['namespaces'] = Namespace.objects.all()
        context['objects'] = get_object_for_observable(observable[0].observable_type, observable[0])
        # get related objects
        for obj in context['objects']:
            context['related_objects'].append(get_related_objects_for_object(obj.id, observable[0].observable_type))
            context['related_observables'].append(obj.observables.all())
        if len(context['related_observables'])<=0:
            context['related_observables'].append(observable)
        # check if observable is in a composition
        for obs_comp in observable[0].observablecomposition_set.all():
            context['related_observables'].append(obs_comp.observable_set.all())
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
        elif observable[0].observable_type == 'CompositionContainer':
            ### TODO: currently supports only single composition in observable
            for composition in observable[0].compositions.all():
                context['composition_id'] = composition.id
    return render_to_response('kraut_intel/observable_details.html', context, context_instance=RequestContext(request))

@login_required
def malware_instance(request, mwi_id="1"):
    """ details of a single malware instance
    """
    context = {'mwi_id': mwi_id, 'mwi': None, 'related_ttps': []}
    try:
        mwi = MalwareInstance.objects.get(pk=int(mwi_id))
    except MalwareInstance.DoesNotExist:
        messages.error(request, 'The requested Malware Instance object does not exist')
        return render_to_response('kraut_intel/mwinstance_details.html', context, context_instance=RequestContext(request))
    context['mwi'] = mwi
    context['namespace_icon'] = get_icon_for_namespace(mwi.ttp_ref.namespace.last().namespace)
    context['description'] = ' '.join(strip_tags(mwi.description).replace('\n', ' ').replace('\r', '').replace('\t', ' ').strip().split())
    return render_to_response('kraut_intel/mwinstance_details.html', context, context_instance=RequestContext(request))

@login_required
def attack_pattern(request, ap_id="1"):
    """ details of a single attack pattern
    """
    context = {'ap_id': ap_id, 'ap': None, 'related_ttps': []}
    try:
        ap = AttackPattern.objects.get(pk=int(ap_id))
    except AttackPattern.DoesNotExist:
        messages.error(request, 'The requested Malware Instance object does not exist')
        return render_to_response('kraut_intel/attpattern_details.html', context, context_instance=RequestContext(request))
    context['ap'] = ap
    context['namespace_icon'] = get_icon_for_namespace(ap.ttp_ref.namespace.last().namespace)
    context['description'] = ' '.join(strip_tags(ap.description).replace('\n', ' ').replace('\r', '').replace('\t', ' ').strip().split())
    return render_to_response('kraut_intel/attpattern_details.html', context, context_instance=RequestContext(request))
