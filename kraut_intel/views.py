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
from kraut_parser.models import AttackPattern, Namespace, Confidence
from kraut_parser.utils import get_object_for_observable, get_related_objects_for_object

from kraut_intel.utils import get_icon_for_namespace
from kraut_intel.forms import PackageForm, PackageCommentForm, ActorCommentForm, ActorForm, CampaignCommentForm, TTPCommentForm
from kraut_intel.models import PackageComment, ThreatActorComment, CampaignComment, TTPComment

import datetime, uuid, argparse

# Create your views here.

@login_required
def home(request):
    context = {}
    return render_to_response('kraut_intel/index.html', context, context_instance=RequestContext(request))

################### PACKAGE #####################

@login_required
def packages(request):
    """ list all intelligence packages
    """
    context = {}
    if hasattr(request.user.userextension, 'namespaces'):
        context['usernamespace'] = request.user.userextension.namespaces.last().namespace.split(':')[0]
        context['namespaceicon'] = get_icon_for_namespace(request.user.userextension.namespaces.last().namespace)
    else:
        context['usernamespace'] = 'nospace'
        context['namespaceicon'] = static('ns_icon/octalpus.png')
    return render_to_response('kraut_intel/packages.html', context, context_instance=RequestContext(request))

@login_required
def add_item_to_package(request, package_id, item_id, item_name):
    """ add an existing item to an existing intelligence package
    """
    if not item_name in ['threatactor', 'campaign','ttp','indicator','observable']:
        messages.error(request, 'Unsupported item type given!')
        return HttpResponseRedirect(reverse('intel:packages'))
    try:
        package = Package.objects.get(pk=int(package_id))
    except Package.DoesNotExist:
        messages.error(request, 'The requested package does not exist!')
        return HttpResponseRedirect(reverse('intel:packages'))
    try:
        if item_name == 'threatactor':
            item = ThreatActor.objects.get(pk=int(item_id))
            package.threat_actors.add(item)
        elif item_name == 'campaign':
            item = Campaign.objects.get(pk=int(item_id))
            package.campaigns.add(item)
        elif item_name == 'ttp':
            item = TTP.objects.get(pk=int(item_id))
            package.ttps.add(item)
        elif item_name == 'indicator':
            item = Indicator.objects.get(pk=int(item_id))
            package.indicators.add(item)
        elif item_name == 'observable':
            item = Observable.objects.get(pk=int(item_id))
            package.observables.add(item)
    except:
        messages.error(request, 'The requested item does not exist! (%s)' % (item_id))
        return HttpResponseRedirect(reverse("intel:package", kwargs={'package_id': package_id}))
    package.save()
    return HttpResponseRedirect(reverse("intel:package", kwargs={'package_id': package_id}))

@login_required
def delete_package(request, package_id="1"):
    """ delete intelligence package with given ID
    """
    try:
        package = Package.objects.get(pk=int(package_id))
    except Package.DoesNotExist:
        messages.error(request, 'The requested package does not exist!')
        return render_to_response('kraut_intel/packages.html', {}, context_instance=RequestContext(request))
    ### TODO: request checkmark to be set to delete attached items too
    ### iterate over observables/objects and delete
    #for ob in package.observables.all():
    #    ### TODO: check for unneeded objects
    #    ob.delete()
    ### iterate over indicators
    #for ic in package.indicators.all():
    #    ic.delete()
    ### iterate over campaigns
    #for ca in package.campaigns.all():
    #    ca.delete()
    ### iterate over threat actors
    #for ta in package.threat_actors.all():
    #    ta.delete()
    ### TODO: delete TTPs
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
            ### make modifications or create new package
            if int(package_id) == 0:
                package = PackageForm(request.POST)
                package.save()
                messages.info(request, 'New Package Created!')
            else:
                p = Package.objects.get(id=package_id)
                package = PackageForm(request.POST, instance=p)
                package.save()
                messages.info(request, 'Package Updated! (%s)' % (package_id))
            return HttpResponseRedirect(reverse('intel:packages'))
        for item in form.errors.as_data():
            messages.error(request, 'Package not valid! %s: %s' % (item, form.errors[item].as_text()))
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
        try:
            context['namespace_icon'] = get_icon_for_namespace(package.namespace.last().namespace)
        except:
            context['namespace_icon'] = get_icon_for_namespace('nospace')
    return render_to_response('kraut_intel/edit_create_package.html', context, context_instance=RequestContext(request))

@login_required
def delete_comment_package(request, package_id="1", comment_id="1"):
    """ delete a comment associated with an intelligence package
    """
    try:
        package = Package.objects.get(pk=int(package_id))
    except Package.DoesNotExist:
        messages.error(request, 'The requested package does not exist!')
        return render_to_response('kraut_intel/packages.html', {}, context_instance=RequestContext(request))
    try:
        cobj = PackageComment.objects.get(pk=int(comment_id),package_reference=package,author=request.user)
    except PackageComment.DoesNotExist:
        messages.error(request, 'The requested comment does not exist!')
    cobj.delete()
    messages.info(request, 'Comment successfully deleted.')
    return HttpResponseRedirect(reverse("intel:package", kwargs={'package_id': package_id}))

@login_required
def comment_package(request, package_id="1"):
    """ add a comment to an intelligence package
    """
    if request.method == "POST":
        form = PackageCommentForm(request.POST)
        if form.is_valid():
            try:
                package = Package.objects.get(pk=int(package_id))
            except Package.DoesNotExist:
                messages.error(request, 'The requested package does not exist!')
                return render_to_response('kraut_intel/packages.html', {}, context_instance=RequestContext(request))
            data = {
                'ctext': form.cleaned_data['ctext'],
                'author': request.user,
                'package_reference': package
            }
            new_comment = PackageComment.objects.get_or_create(**data)
            messages.info(request, "Comment successfully added")
        else:
            if form.errors:
                for field in form:
                    for error in field.errors:
                        messages.error(request, '%s: %s' % (field.name, error))
    return HttpResponseRedirect(reverse("intel:package", kwargs={'package_id': package_id}))

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
        try:
            comments = PackageComment.objects.filter(package_reference=package[0]).order_by('-creation_time')
        except:
            comments = None
        context['comments'] = comments
        context['commentform'] = PackageCommentForm()
        context['package'] = package[0]
        if package[0].description:
            context['description'] = ' '.join(package[0].description.strip().split())
        else:
            context['description'] = ''
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
        for ind_obj in package[0].indicators.all():
            for obs_obj in ind_obj.observable_set.all():
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

################### THREAT ACTOR #####################

@login_required
def edit_create_threatactor(request, threat_actor_id):
    """ create a new threat actor or edit an existing one
    """
    context = {}
    if request.method == 'POST':
        form = ActorForm(request.POST)
        if form.is_valid():
            if int(threat_actor_id) == 0:
                actor = ActorForm(request.POST)
                actor.save()
                messages.info(request, 'New Threat Actor Created!')
            else:
                a = ThreatActor.objects.get(id=threat_actor_id)
                actor = ActorForm(request.POST, instance=a)
                actor.save()
                messages.info(request, 'Threat Actor Updated! (%s)' % (threat_actor_id))
            return HttpResponseRedirect(reverse('intel:threatactors'))
        for item in form.errors.as_data():
            messages.error(request, 'Package not valid! %s: %s' % (item, form.errors[item].as_text()))
        return HttpResponseRedirect(reverse('intel:edit_create_threatactor', kwargs={'threat_actor_id': threat_actor_id}))
    else:
        if int(threat_actor_id)>0:
            try:
                actor = ThreatActor.objects.get(pk=int(threat_actor_id))
            except ThreatActor.DoesNotExist:
                messages.error(request, 'The requested threat actor does not exist!')
                return render_to_response('kraut_intel/threatactors.html', {}, context_instance=RequestContext(request))
        else:
            actor = None
        if actor:
            defaults = {
                'name': actor.name,
                'description': actor.description,
                'short_description': actor.short_description,
                'threat_actor_id': actor.threat_actor_id
            }
            defaults['namespace'] = [b.pk for b in actor.namespace.all()]
            form = ActorForm(defaults, instance=actor)
        else:
            actor_dict = {'name': 'Create New Threat Actor'}
            actor = argparse.Namespace(**actor_dict)
            defaults = {
                'threat_actor_id': 'nospace:threatactor-%s' % (uuid.uuid4())
            }
            form = ActorForm(defaults)
        context['form'] = form
        context['actor_id'] = threat_actor_id
        context['actor'] = actor
        try:
            context['namespace_icon'] = get_icon_for_namespace(actor.namespace.last().namespace)
        except:
            context['namespace_icon'] = get_icon_for_namespace('nospace')
    return render_to_response('kraut_intel/edit_create_actor.html', context, context_instance=RequestContext(request))


@login_required
def threatactors(request):
    context = {}
    if hasattr(request.user.userextension, 'namespaces'):
        context['usernamespace'] = request.user.userextension.namespaces.last().namespace.split(':')[0]
        context['namespaceicon'] = get_icon_for_namespace(request.user.userextension.namespaces.last().namespace)
    else:
        context['usernamespace'] = 'nospace'
        context['namespaceicon'] = static('ns_icon/octalpus.png')
    return render_to_response('kraut_intel/threatactors.html', context, context_instance=RequestContext(request))

@login_required
def delete_comment_actor(request, threat_actor_id="1", comment_id="1"):
    """ delete a comment associated with a threat actor
    """
    try:
        actor = ThreatActor.objects.get(pk=int(threat_actor_id))
    except ThreatActor.DoesNotExist:
        messages.error(request, 'The requested threat actor does not exist!')
        return HttpResponseRedirect(reverse('intel:threatactors'))
    try:
        cobj = ThreatActorComment.objects.get(pk=int(comment_id),actor_reference=actor,author=request.user)
    except ThreatActorComment.DoesNotExist:
        messages.error(request, 'The requested comment does not exist!')
    cobj.delete()
    messages.info(request, 'Comment successfully deleted.')
    return HttpResponseRedirect(reverse("intel:threatactor", kwargs={'threat_actor_id': threat_actor_id}))

@login_required
def comment_actor(request, threat_actor_id="1"):
    """ add a comment to a threat actor
    """
    if request.method == "POST":
        form = ActorCommentForm(request.POST)
        if form.is_valid():
            try:
                actor = ThreatActor.objects.get(pk=int(threat_actor_id))
            except ThreatActor.DoesNotExist:
                messages.error(request, 'The requested threat actor does not exist!')
                return HttpResponseRedirect(reverse('intel:threatactors'))
            data = {
                'ctext': form.cleaned_data['ctext'],
                'author': request.user,
                'actor_reference': actor
            }
            new_comment = ThreatActorComment.objects.get_or_create(**data)
            messages.info(request, "Comment successfully added")
        else:
            if form.errors:
                for field in form:
                    for error in field.errors:
                        messages.error(request, '%s: %s' % (field.name, error))
    return HttpResponseRedirect(reverse("intel:threatactor", kwargs={'threat_actor_id': threat_actor_id}))

@login_required
def update_ta_header(request, threat_actor_id="1"):
    """ update header information of given threat actor
    """
    try:
        actor = ThreatActor.objects.get(pk=int(threat_actor_id))
    except ThreatActor.DoesNotExist:
        messages.error(request, 'The requested threat actor does not exist!')
        return HttpResponseRedirect(reverse('intel:threatactors'))
    if request.method == "POST":
        ta_name = request.POST.get('ta_name', None)
        ta_types = request.POST.get('ta_types', None)
        ta_roles = request.POST.get('ta_roles', None)
        ta_ns = request.POST.get('ta_namespace', None)
        ta_descr = request.POST.get('ta_description', None)
        if ta_name:
            actor.name = ta_name
        if ta_types:
            ### remove all old types for this TA
            TA_Types.objects.filter(actor=actor).delete()
            ttypes_list = ta_types.split(',')
            for item in ttypes_list:
                if item.strip() == 'Unknown':
                    continue
                ta_type_object, ta_type_created = TA_Types.objects.get_or_create(ta_type=item.strip(), actor=actor)
        else:
            TA_Types.objects.filter(actor=actor).delete()
        if ta_roles:
            ### remove all old roles for this TA
            TA_Roles.objects.filter(actor=actor).delete()
            troles_list = ta_roles.split(',')
            for item in troles_list:
                if item.strip() == 'Unknown':
                    continue
                ta_role_object, ta_role_created = TA_Roles.objects.get_or_create(role=item.strip(), actor=actor)
        else:
            TA_Roles.objects.filter(actor=actor).delete()
        if ta_ns:
            ns_obj, ns_created = Namespace.objects.get_or_create(namespace=ta_ns)
            actor.namespace.clear()
            actor.namespace.add(ns_obj)
        if ta_descr:
            actor.description = ta_descr
        actor.save()
    return HttpResponseRedirect(reverse("intel:threatactor", kwargs={'threat_actor_id': threat_actor_id}))

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
        try:
            comments = ThreatActorComment.objects.filter(actor_reference=ta[0]).order_by('-creation_time')
        except:
            comments = None
        context['comments'] = comments
        context['commentform'] = ActorCommentForm()
        context['ta'] = ta[0]
        ### Get TA Types
        try:
            ta_types = TA_Types.objects.filter(actor=ta[0])
            #ta_type = ta_type_object.ta_type
        except TA_Types.DoesNotExist:
            ta_types = [{'ta_type': "Unknown"}]
        ta_types_string = ""
        for item in ta_types:
            ta_types_string += '%s, ' % (item.ta_type)
        ta_types_string = ta_types_string.strip()[:-1]
        if ta_types_string == "":
            ta_types_string = "Unknown"
        ### Get TA Roles
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
        ### Get TA Alias Names
        try:
            ta_alias = TA_Alias.objects.filter(actor=ta[0])
        except TA_Alias.DoesNotExist:
            ta_alias = None
        context['ta_types'] = ta_types_string
        context['ta_roles'] = ta_roles_string
        context['ta_alias'] = ta_alias
        context['namespaces'] = Namespace.objects.all()
        context['namespace_icon'] = get_icon_for_namespace(ta[0].namespace)
        context['tab'] = 'campaigns'
        context['num_campaigns'] = ta[0].campaigns.count()
        context['num_assoc_ta'] = ta[0].associated_threat_actors.count()
        context['num_ttps'] = ta[0].observed_ttps.count()
    return render_to_response('kraut_intel/threatactor_details.html', context, context_instance=RequestContext(request))

################### CAMPAIGNS #####################

@login_required
def campaigns(request):
    context = {}
    if hasattr(request.user.userextension, 'namespaces'):
        context['usernamespace'] = request.user.userextension.namespaces.last().namespace.split(':')[0]
        context['namespaceicon'] = get_icon_for_namespace(request.user.userextension.namespaces.last().namespace)
    else:
        context['usernamespace'] = 'nospace'
        context['namespaceicon'] = static('ns_icon/octalpus.png')
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
        try:
            comments = CampaignComment.objects.filter(campaign_reference=campaign[0]).order_by('-creation_time')
        except:
            comments = None
        context['comments'] = comments
        context['commentform'] = CampaignCommentForm()
        context['campaign'] = campaign[0]
        context['confidences'] = Confidence.objects.all()
        context['namespaces'] = Namespace.objects.all()
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
def delete_comment_campaign(request, campaign_id="1", comment_id="1"):
    """ delete a comment associated with a threat campaign
    """
    try:
        campaign = Campaign.objects.get(pk=int(campaign_id))
    except Campaign.DoesNotExist:
        messages.error(request, 'The requested campaign does not exist!')
        return HttpResponseRedirect(reverse('intel:campaigns'))
    try:
        cobj = CampaignComment.objects.get(pk=int(comment_id),campaign_reference=campaign,author=request.user)
    except CampaignComment.DoesNotExist:
        messages.error(request, 'The requested comment does not exist!')
    cobj.delete()
    messages.info(request, 'Comment successfully deleted.')
    return HttpResponseRedirect(reverse("intel:campaign", kwargs={'campaign_id': campaign_id}))


@login_required
def comment_campaign(request, campaign_id):
    """add a comment to a campaign object
    """
    if request.method == "POST":
        form = CampaignCommentForm(request.POST)
        if form.is_valid():
            try:
                campaign = Campaign.objects.get(pk=int(campaign_id))
            except Campaign.DoesNotExist:
                messages.error(request, 'The requested campaign does not exist!')
                return render_to_response('kraut_intel/campaigns.html', {}, context_instance=RequestContext(request))
            data = {
                'ctext': form.cleaned_data['ctext'],
                'author': request.user,
                'campaign_reference': campaign
            }
            new_comment = CampaignComment.objects.get_or_create(**data)
            messages.info(request, "Comment successfully added")
        else:
            if form.errors:
                for field in form:
                    for error in field.errors:
                        messages.error(request, '%s: %s' % (field.name, error))
    return HttpResponseRedirect(reverse("intel:campaign", kwargs={'campaign_id': campaign_id}))

@login_required
def update_campaign_header(request, campaign_id):
    """ update header information of given campaign (kraut editor)
    """
    try:
        campaign = Campaign.objects.get(pk=int(campaign_id))
    except Campaign.DoesNotExist:
        messages.error(request, "The requested campaign does not exist!")
        return render_to_response('kraut_intel/campaigns.html', {}, context_instance=RequestContext(request))
    if request.method == "POST":
        campaign_name = request.POST.get('campaign_name', None)
        campaign_status = request.POST.get('campaign_status', None)
        campaign_confidence = request.POST.get('campaign_confidence', None)
        campaign_ns = request.POST.get('campaign_namespace', None)
        campaign_descr = request.POST.get('campaign_description', None)
        if campaign_name:
            campaign.name = campaign_name
        if campaign_status:
            campaign.status = campaign_status
        if campaign_confidence:
            try:
                cobj = Confidence.objects.get(value=campaign_confidence)
                campaign.confidence.clear()
                campaign.confidence.add(cobj)
            except Exception as e:
                messages.error(request, "Failed updating confidence: %s" % (e))
        if campaign_ns:
            ns_obj, ns_created = Namespace.objects.get_or_create(namespace=campaign_ns)
            campaign.namespace.clear()
            campaign.namespace.add(ns_obj)
        if campaign_descr:
            campaign.description = campaign_descr
        campaign.save()
    return HttpResponseRedirect(reverse("intel:campaign", kwargs={'campaign_id': campaign_id}))


@login_required
def delete_campaign(request, campaign_id):
    """ delete campaign object and all associated objects
    """
    try:
        campaign = Campaign.objects.get(pk=int(campaign_id))
    except Campaign.DoesNotExist:
        messages.error(request, "The requested campaign does not exist!")
        return render_to_response('kraut_intel/campaigns.html', {}, context_instance=RequestContext(request))
    ### TODO: delete associated objects
    # delete campaign
    campaign.delete()
    messages.info(request, 'The campaign was deleted successfully!')
    return HttpResponseRedirect(reverse('intel:campaigns'))

@login_required
def ttps(request):
    context = {}
    if hasattr(request.user.userextension, 'namespaces'):
        context['usernamespace'] = request.user.userextension.namespaces.last().namespace.split(':')[0]
        context['namespaceicon'] = get_icon_for_namespace(request.user.userextension.namespaces.last().namespace)
    else:
        context['usernamespace'] = 'nospace'
        context['namespaceicon'] = static('ns_icon/octalpus.png')
    return render_to_response('kraut_intel/ttps.html', context, context_instance=RequestContext(request))

@login_required
def delete_comment_ttp(request, ttp_id="1", comment_id="1"):
    """ delete a comment associated with a ttp
    """
    try:
        ttp = TTP.objects.get(pk=int(ttp_id))
    except TTP.DoesNotExist:
        messages.error(request, 'The requested ttp does not exist!')
    	return HttpResponseRedirect(reverse('intel:ttps'))
    try:
        cobj = TTPComment.objects.get(pk=int(comment_id),ttp_reference=ttp,author=request.user)
    except TTPComment.DoesNotExist:
        messages.error(request, 'The requested comment does not exist!')
    cobj.delete()
    messages.info(request, 'Comment successfully deleted.')
    return HttpResponseRedirect(reverse("intel:ttp", kwargs={'ttp_id': ttp_id}))

@login_required
def comment_ttp(request, ttp_id="1"):
    """ add a comment to a ttp
    """
    if request.method == "POST":
        form = TTPCommentForm(request.POST)
        if form.is_valid():
            try:
                ttp = TTP.objects.get(pk=int(ttp_id))
            except TTP.DoesNotExist:
                messages.error(request, 'The requested ttp does not exist!')
                return HttpResponseRedirect(reverse('intel:ttps'))
            data = {
                'ctext': form.cleaned_data['ctext'],
                'author': request.user,
                'ttp_reference': ttp
            }
            new_comment = TTPComment.objects.get_or_create(**data)
            messages.info(request, "Comment successfully added")
        else:
            if form.errors:
                for field in form:
                    for error in field.errors:
                        messages.error(request, '%s: %s' % (field.name, error))
    return HttpResponseRedirect(reverse("intel:ttp", kwargs={'ttp_id': ttp_id}))


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
        try:
            comments = TTPComment.objects.filter(ttp_reference=ttp[0]).order_by('-creation_time')
        except:
            comments = None
        context['comments'] = comments
        context['commentform'] = TTPCommentForm()
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
def delete_ttp(request, ttp_id):
    """ delete ttp object and all associated objects
    """
    try:
        ttp = TTP.objects.get(pk=int(ttp_id))
    except TTP.DoesNotExist:
        messages.error(request, 'The requested TTP does not exist!')
        return render_to_response('kraut_intel/ttps.html', {}, context_instance=RequestContext(request))
    ### TODO: delete associated objects, if special flag is set
    # delete ttp
    ttp.delete()
    messages.info(request, 'The TTP was deleted successfully!')
    return HttpResponseRedirect(reverse('intel:ttps'))

@login_required
def indicators(request):
    context = {}
    return render_to_response('kraut_intel/indicators.html', context, context_instance=RequestContext(request))

@login_required
def update_indicator_header(request, indicator_id="1"):
    """ update indicator header information
    """
    try:
        indicator = Indicator.objects.get(pk=int(indicator_id))
    except Indicator.DoesNotExist:
        messages.error(request, 'The requested indicator does not exist!')
        return render_to_response('kraut_intel/indicators.html', {}, context_instance=RequestContext(request))
    if request.method == "POST":
        ind_name = request.POST.get('indicator_name', None)
        ind_namespace = request.POST.get('indicator_namespace', None)
        ind_description = request.POST.get('indicator_description', None)
        ind_confidence = request.POST.get('indicator_confidence', None)
        if ind_name:
            indicator.name = ind_name
        if ind_confidence:
            indc_obj, indc_created = Confidence.objects.get_or_create(value=ind_confidence)
            indicator.confidence.clear()
            indicator.confidence.add(indc_obj)
        if ind_namespace:
            ind_obj, ind_created = Namespace.objects.get_or_create(namespace=ind_namespace)
            indicator.namespace.clear()
            indicator.namespace.add(ind_obj)
        if ind_description:
            indicator.description = ind_description
        indicator.save()
    return HttpResponseRedirect(reverse("intel:indicator", kwargs={'indicator_id': indicator_id}))

@login_required
def delete_indicator(request, indicator_id):
    """ delete indicator
    """
    try:
        indicator = Indicator.objects.get(pk=int(indicator_id))
    except Indicator.DoesNotExist:
        messages.error(request, 'The requested indicator does not exist!')
        return render_to_response('kraut_intel/indicators.html', {}, context_instance=RequestContext(request))
    ### TODO: delete associated object, if flag is set
    # delete indicator
    indicator.delete()
    messages.info(request, 'The indicator was deleted successfully!')
    return HttpResponseRedirect(reverse('intel:indicators'))

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
            Prefetch('observablecomposition_set'),
            Prefetch('ttps'),
            Prefetch('kill_chain_phases')
        )
    except Indicator.DoesNotExist:
        messages.error(request, "The requested indicator does not exist!")
        return render_to_response('kraut_intel/indicator_details.html', context, context_instance=RequestContext(request))
    if len(indicator)<=0:
        messages.warning(request, "No indicator with the given ID exists in the system.")
    else:
        context['indicator'] = indicator[0]
        context['namespace_icon'] = get_icon_for_namespace(indicator[0].namespace)
        context['namespaces'] = Namespace.objects.all()
        context['num_killchain'] = indicator[0].kill_chain_phases.count()
        context['num_ttps'] = indicator[0].ttps.count()
        context['num_indicators'] = indicator[0].related_indicators.count()
        context['num_observables'] = indicator[0].observable_set.count()
        context['num_observable_compositions'] = indicator[0].observablecomposition_set.count()
        if context['num_indicators'] > 0:
            context['tab'] = 'indicators'
        elif context['num_observables'] > 0:
            context['tab'] = 'observables'
        elif context['num_observable_compositions'] > 0:
            context['tab'] = 'compositions'
        elif context['num_ttps'] > 0:
            context['tab'] = 'ttps'
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
def delete_observable(request, observable_id):
    """ delete given observable
    """
    try:
        obs = Observable.objects.get(pk=int(observable_id))
    except Observable.DoesNotExist:
        messages.info(request, 'The observable was deleted successfully!')
        return render_to_response('kraut_intel/observables.html', {}, context_instance=RequestContext(request))
    ### TODO: delete associated objects
    # delete observable
    obs.delete()
    messages.info(request, 'The observable was deleted successfully!')
    return HttpResponseRedirect(reverse("intel:observables"))

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
        elif observable[0].observable_type == 'WindowsExecutableFileObjectType':
            context['active_tab'] = 'winexeobj'
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
