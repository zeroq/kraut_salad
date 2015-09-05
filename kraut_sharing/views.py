# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.shortcuts import render_to_response, redirect
from django.template import RequestContext

from kraut_sharing.forms import DiscoveryForm

# Create your views here.

def home(request):
    context = {}
    form = DiscoveryForm()
    context['form'] = form
    return render_to_response('kraut_sharing/index.html', context, context_instance=RequestContext(request))


