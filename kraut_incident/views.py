# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.shortcuts import render_to_response
from django.template import RequestContext

# Create your views here.

def home(request):
    context = {}
    return render_to_response('kraut_incident/index.html', context, context_instance=RequestContext(request))

def list_incidents(request):
    context = {}
    return render_to_response('kraut_incident/list.html', context, context_instance=RequestContext(request))

def new_incident(request):
    context = {}
    return render_to_response('kraut_incident/new.html', context, context_instance=RequestContext(request))
