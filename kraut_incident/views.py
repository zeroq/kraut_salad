# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

import json

from django.http import HttpResponseRedirect, HttpResponse
from django.core.urlresolvers import reverse
from django.shortcuts import render_to_response
from django.template import RequestContext
from django.contrib import messages

from kraut_incident.forms import IncidentForm, ContactForm, HandlerForm
from kraut_incident.models import Contact, Handler, Incident

# Create your views here.

def home(request):
    context = {}
    return render_to_response('kraut_incident/index.html', context, context_instance=RequestContext(request))

def list_incidents(request):
    context = {}
    return render_to_response('kraut_incident/list.html', context, context_instance=RequestContext(request))

def create_handler(request):
    """This function is called from within the incident creation dialog to instantly add a new incident handler
    """
    context = {}
    if request.method == 'POST':
        handler_form = HandlerForm(request.POST)
        if handler_form.is_valid():
            new_handler = Handler.objects.get_or_create(**handler_form.cleaned_data)
            response_data = {'result': 'info', 'message': json.dumps({'info': [{'message': 'handler succesfully created!'}]})}
        else:
            response_data = {'result': 'danger', 'message': handler_form.errors.as_json()}
        return HttpResponse(json.dumps(response_data), content_type="application/json")
    else:
        return HttpResponse(json.dumps({"nothing to see": "this isn't happening"}), content_type="application/json")

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
        ### {'status': <Incident_Status: Open>, 'incident_number': 4976401221, 'category': <Incident_Category: Investigation>, 'description': u'', 'title': u'Unnamed Incident'}
        incident_form = IncidentForm(request.POST)
        if incident_form.is_valid():
            print incident_form.cleaned_data
            new_incident = Incident(
                incident_number = incident_form.cleaned_data['incident_number'],
                title = incident_form.cleaned_data['title'],
                description = incident_form.cleaned_data['description'],
                status = incident_form.cleaned_data['status'],
                category = incident_form.cleaned_data['category']
            )
            new_incident.save()
            for key in request.POST:
                if key.startswith('HandlerCheckBox'):
                    handler_id = request.POST[key]
                    try:
                        handler = Handler.objects.get(pk=handler_id)
                        new_incident.incident_handler.add(handler)
                    except Handler.DoesNotExist:
                        messages.error(request, 'Failed getting incident handler with ID: %s' % (handler_id))
                elif key.startswith('ContactCheckBox'):
                    contact_id = request.POST[key]
                    try:
                        contact = Contact.objects.get(pk=contact_id)
                        new_incident.contacts.add(contact)
                    except Contact.DoesNotExist:
                        messages.error(request, 'Failed getting incident contact with ID: %s' % (contact_id))
            new_incident.save()
            messages.info(request, "Incident successfully created!")
        return HttpResponseRedirect(reverse("incidents:new"))
    incident_form = IncidentForm(initial={'status': 1, 'category': 7})
    contact_form = ContactForm()
    handler_form = HandlerForm()
    context['formset'] = incident_form
    context['contact_form'] = contact_form
    context['handler_form'] = handler_form
    return render_to_response('kraut_incident/new.html', context, context_instance=RequestContext(request))
