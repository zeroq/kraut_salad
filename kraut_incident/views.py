# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

import json

from django.http import HttpResponseRedirect, HttpResponse
from django.urls import reverse
from django.shortcuts import render
from django.template import RequestContext
from django.contrib import messages
from django.contrib.auth.decorators import login_required

from kraut_intel.utils import get_icon_for_namespace

from kraut_incident.forms import IncidentForm, ContactForm, HandlerForm
from kraut_incident.models import Contact, Handler, Incident
from kraut_incident.utils import slicedict

# Create your views here.

@login_required
def home(request):
    context = {}
    return render(request, 'kraut_incident/index.html', context)

@login_required
def list_incidents(request):
    context = {}
    return render(request, 'kraut_incident/incident_list.html', context)

@login_required
def update_incident_header(request, incident_id):
    """Update incident header information
    """
    context = {}
    return render(request, 'kraut_incident/incident_list.html', context)

@login_required
def comment_incident(request, incident_id):
    context = {}
    return render(request, 'kraut_incident/incident_list.html', context)



@login_required
def view_incident(request, incident_id):
    """View details of incident
    """
    context = {'incident_id': incident_id, 'incident': None}
    try:
        inc = Incident.objects.get(id=incident_id)
    except Incident.DoesNotExist:
        messages.error(request, 'The requested incident does not exist!')
        return render(request, 'kraut_incident/incident_list.html', context)
    context['incident'] = inc
    context['severities'] = ['High', 'Medium', 'Low']
    if inc.severity == 'h':
        context['severity'] = 'High'
    elif inc.severity == 'm':
        context['severity'] = 'Medium'
    else:
        context['severity'] = 'Low'
    if hasattr(request.user.userextension, 'namespaces'):
        context['usernamespace'] = request.user.userextension.namespaces.last().namespace.split(':')[0]
        context['namespaceicon'] = get_icon_for_namespace(request.user.userextension.namespaces.last().namespace)
    else:
        context['usernamespace'] = 'nospace'
        context['namespaceicon'] = static('ns_icon/octalpus.png')
    context['num_incident_handlers'] = inc.incident_handler.count()
    context['num_incident_contacts'] = inc.contacts.count()
    context['num_incident_tasks'] = inc.tasks.count()
    if context['num_incident_tasks'] > 0:
        context['tab'] = 'incident_tasks'
    elif context['num_incident_contacts'] > 0:
        context['tab'] = 'incident_contacts'
    else:
        context['tab'] = 'incident_handlers'
    return render(request, 'kraut_incident/incident_details.html', context)

@login_required
def delete_incident(request, incident_id):
    """Delete incident with given ID
    """
    context = {}
    try:
        inc = Incident.objects.get(id=incident_id)
    except Incident.DoesNotExist:
        messages.error(request, 'The requested incident does not exist!')
        return render(request, 'kraut_incident/incident_list.html', context)
    inc.delete()
    messages.info(request, 'The incident was deleted successfully!')
    return HttpResponseRedirect(reverse('incidents:list'))

@login_required
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

@login_required
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

@login_required
def new_incident(request):
    context = {}
    if request.method == 'POST':
        ### {'status': <Incident_Status: Open>, 'incident_number': 4976401221, 'category': <Incident_Category: Investigation>, 'description': u'', 'title': u'Unnamed Incident'}
        incident_form = IncidentForm(request.POST)
        if incident_form.is_valid():
            # check if handler and contact given
            handler_dict = slicedict(request.POST, 'HandlerCheckBox')
            contact_dict = slicedict(request.POST, 'ContactCheckBox')
            if len(handler_dict)<=0:
                messages.error(request, 'Missing an incident handler!')
                return HttpResponseRedirect(reverse("incidents:new"))
            if len(contact_dict)<=0:
                messages.error(request, 'Missing an incident contact!')
                return HttpResponseRedirect(reverse("incidents:new"))
            new_incident = Incident(
                incident_number = incident_form.cleaned_data['incident_number'],
                title = incident_form.cleaned_data['title'],
                description = incident_form.cleaned_data['description'],
                status = incident_form.cleaned_data['status'],
                category = incident_form.cleaned_data['category'],
                severity = incident_form.cleaned_data['severity']
            )
            new_incident.save()
            for key in handler_dict:
                handler_id = handler_dict[key]
                try:
                    handler = Handler.objects.get(pk=handler_id)
                    new_incident.incident_handler.add(handler)
                except Handler.DoesNotExist:
                    messages.error(request, 'Failed getting incident handler with ID: %s' % (handler_id))
            for key in contact_dict:
                contact_id = contact_dict[key]
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
    if hasattr(request.user.userextension, 'namespaces'):
        context['usernamespace'] = request.user.userextension.namespaces.last().namespace.split(':')[0]
        context['namespaceicon'] = get_icon_for_namespace(request.user.userextension.namespaces.last().namespace)
    else:
        context['usernamespace'] = 'nospace'
        context['namespaceicon'] = static('ns_icon/octalpus.png')
    return render(request, 'kraut_incident/incident_new.html', context)
