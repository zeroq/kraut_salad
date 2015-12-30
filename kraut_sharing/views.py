# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

import datetime, pytz

from django.shortcuts import render_to_response
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.template import RequestContext
from django.contrib import messages

from kraut_sharing.forms import DiscoveryForm, PollForm, AddServerForm
from kraut_sharing.models import TAXII_Remote_Server

# Create your views here.

def home(request):
    """ discovery feeds available at a TAXII server """
    context = {}
    form = DiscoveryForm()
    context['form'] = form
    return render_to_response('kraut_sharing/index.html', context, context_instance=RequestContext(request))

def manage_servers(request):
    """ manage taxii servers """
    context = {}
    if not request.method == 'POST':
        serverForm = AddServerForm()
        context['form'] = serverForm
        return render_to_response('kraut_sharing/servers.html', context, context_instance=RequestContext(request))
    serverForm = AddServerForm(request.POST)
    if serverForm.is_valid():
        oldID = int(request.POST.get('oldid', 0))
        if oldID == 0:
            new_server = TAXII_Remote_Server.objects.get_or_create(**serverForm.cleaned_data)
            messages.info(request, 'Successfully added new TAXII server!')
        else:
            old_server = TAXII_Remote_Server.objects.filter(id=oldID).update(**serverForm.cleaned_data)
            messages.info(request, 'Successfully updated TAXII server!')
    else:
        if serverForm.errors:
            for field in serverForm:
                for error in field.errors:
                    messages.error(request, '%s: %s' % (field.name, error))
    context['form'] = serverForm
    return HttpResponseRedirect(reverse("sharing:servers"))

def delete_server(request, server_id):
    """ delete TAXII server """
    try:
        server = TAXII_Remote_Server.objects.get(pk=int(server_id))
    except TAXII_Remote_Server.DoesNotExist:
        messages.error(request, 'The requested TAXII server does not exist!')
        return HttpResponseRedirect(reverse("sharing:servers"))
    # TODO: check for associated collections and subscriptions
    server.delete()
    messages.info(request, 'The TAXII server was deleted successfully!')
    return HttpResponseRedirect(reverse("sharing:servers"))

def poll(request):
    """ poll feed information """
    context = {}
    # set begin time by default to 24 hours ago
    begin_time = datetime.datetime.now(pytz.utc) - datetime.timedelta(hours = 24)
    if not request.method == 'POST':
        form = PollForm(initial={'begin_time': begin_time.strftime('%Y-%m-%dT%H:%M:%S.%f%z')})
        context['form'] = form
        return render_to_response('kraut_sharing/poll.html', context, context_instance=RequestContext(request))
    form = PollForm(initial={'url': request.POST.get('url'), 'service': request.POST.get('service'), 'begin_time': begin_time.strftime('%Y-%m-%dT%H:%M:%S.%f%z')})
    context['form'] = form
    messages.info(request, 'Polling intelligence ...')
    return render_to_response('kraut_sharing/poll.html', context, context_instance=RequestContext(request))
