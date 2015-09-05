# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

import datetime, pytz

from django.shortcuts import render_to_response, redirect
from django.template import RequestContext
from django.contrib import messages

from kraut_sharing.forms import DiscoveryForm, PollForm

# Create your views here.

def home(request):
    """ discovery feeds available at a TAXII server """
    context = {}
    form = DiscoveryForm()
    context['form'] = form
    return render_to_response('kraut_sharing/index.html', context, context_instance=RequestContext(request))


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
    return render_to_response('kraut_sharing/poll.html', context, context_instance=RequestContext(request))
