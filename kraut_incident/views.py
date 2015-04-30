# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

import json

from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.contrib import messages

from kraut_incident.forms import IncidentForm, ContactForm
from kraut_incident.models import Contact

# Create your views here.

def home(request):
    context = {}
    return render_to_response('kraut_incident/index.html', context, context_instance=RequestContext(request))

def list_incidents(request):
    context = {}
    return render_to_response('kraut_incident/list.html', context, context_instance=RequestContext(request))

def create_contact(request):
    """This function is called from within the incident creation dialog to instantly add a new contact
    """
    context = {}
    if request.method == 'POST':
        contact_form = ContactForm(request.POST)
        if contact_form.is_valid():
            new_contact = Contact.objects.get_or_create(**contact_form.cleaned_data)
            response_data = {'result': 'info', 'message': json.dumps({'info': [{'message': 'contact succesfully created!'}]})}
        else:
            response_data = {'result': 'danger', 'message': contact_form.errors.as_json()}
        return HttpResponse(json.dumps(response_data), content_type="application/json")
    else:
        return HttpResponse(json.dumps({"nothing to see": "this isn't happening"}), content_type="application/json")

def new_incident(request):
    context = {}
    if request.method == 'POST':
        print request.POST
        incident_form = IncidentForm(request.POST)
        if incident_form.is_valid():
            messages.info(request, "Incident successfully created!")
        return HttpResponseRedirect(reverse("incidents:new"))
    incident_form = IncidentForm(initial={'status': 1, 'category': 7})
    contact_form = ContactForm()
    context['formset'] = incident_form
    context['contact_form'] = contact_form
    return render_to_response('kraut_incident/new.html', context, context_instance=RequestContext(request))
