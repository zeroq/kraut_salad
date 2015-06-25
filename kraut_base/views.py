# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.shortcuts import render_to_response
from django.template import RequestContext

from kraut_parser.models import Package, ThreatActor, Campaign, Indicator, Observable, TTP

# Create your views here.

def home(request):
    context = {'indicators': 0, 'observables': 0, 'campaigns': 0, 'threatactors': 0, 'packages': 0}
    context['packages'] = Package.objects.count()
    context['threatactors'] = ThreatActor.objects.count()
    context['campaigns'] = Campaign.objects.count()
    context['ttps'] = TTP.objects.count()
    context['indicators'] = Indicator.objects.count()
    context['observables'] = Observable.objects.count()
    return render_to_response('kraut_base/index.html', context, context_instance=RequestContext(request))
