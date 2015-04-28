# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.contrib import messages

from kraut_incident.forms import IncidentForm, ContactForm

# Create your views here.

def home(request):
    context = {}
    return render_to_response('kraut_incident/index.html', context, context_instance=RequestContext(request))

def list_incidents(request):
    context = {}
    return render_to_response('kraut_incident/list.html', context, context_instance=RequestContext(request))

def new_incident(request):
    context = {}
    if request.method == 'POST':
        incident_form = IncidentForm(request.POST)
        if incident_form.is_valid():
            messages.info(request, "Incident successfully created!")
        return HttpResponseRedirect(reverse("incidents:new"))
    incident_form = IncidentForm(initial={'status': 1, 'category': 7})
    contact_form = ContactForm()
    context['formset'] = incident_form
    context['contact_form'] = contact_form
    return render_to_response('kraut_incident/new.html', context, context_instance=RequestContext(request))
