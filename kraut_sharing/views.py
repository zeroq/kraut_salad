# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.shortcuts import render_to_response, redirect
from django.template import RequestContext

from kraut_sharing.tasks import taxii_discovery
from kraut_sharing.forms import DiscoveryForm

# Create your views here.

def home(request):
    context = {}
    if request.method == 'POST':
        form = DiscoveryForm(request.POST)
        if form.is_valid():
            taxii_discovery.delay(form.cleaned_data['url'])
        context['form'] = form
        return redirect('sharing:discover', permanent=True)
    else:
        form = DiscoveryForm()
        context['form'] = form
    return render_to_response('kraut_sharing/index.html', context, context_instance=RequestContext(request))

def discover(request):
    context = {}
    return render_to_response('kraut_sharing/discover.html', context, context_instance=RequestContext(request))

