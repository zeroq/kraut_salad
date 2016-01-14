# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.shortcuts import render_to_response
from django.template import RequestContext
from django.contrib.auth.decorators import login_required
from django.templatetags.static import static

from kraut_intel.utils import get_icon_for_namespace

from kraut_parser.models import Package, ThreatActor, Campaign, Indicator, Observable, TTP

# Create your views here.

@login_required
def home(request):
    context = {'indicators': 0, 'observables': 0, 'campaigns': 0, 'threatactors': 0, 'packages': 0}
    context['packages'] = Package.objects.count()
    context['threatactors'] = ThreatActor.objects.count()
    context['campaigns'] = Campaign.objects.count()
    context['ttps'] = TTP.objects.count()
    context['indicators'] = Indicator.objects.count()
    context['observables'] = Observable.objects.count()
    if hasattr(request.user.userextension, 'namespaces'):
        context['usernamespace'] = request.user.userextension.namespaces.last().namespace.split(':')[0]
        context['namespaceicon'] = get_icon_for_namespace(request.user.userextension.namespaces.last().namespace)
    else:
        context['usernamespace'] = 'nospace'
        context['namespaceicon'] = static('ns_icon/octalpus.png')
    return render_to_response('kraut_base/index.html', context, context_instance=RequestContext(request))
