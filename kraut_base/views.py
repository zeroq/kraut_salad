# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.shortcuts import render_to_response
from django.template import RequestContext

# Create your views here.

def home(request):
    context = {}
    return render_to_response('kraut_base/index.html', context, context_instance=RequestContext(request))
