# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

import json

from django.http import HttpResponseRedirect, HttpResponse
from django.urls import reverse
from django.shortcuts import render
from django.template import RequestContext
from django.contrib import messages
from django.contrib.auth.decorators import login_required

from kraut_intel.utils import get_icon_for_namespace

from kraut_incident.forms import IncidentForm, ContactForm, HandlerForm, IncidentCommentForm
from kraut_incident.models import Contact, Handler, Incident, IncidentComment, TemplateTask, Task
from kraut_incident.utils import slicedict

import datetime

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
def abort_task_incident(request, incident_id, task_id):
    """abort a task from an incident
    """
    context = {}
    try:
        inc = Incident.objects.get(id=incident_id)
    except Incident.DoesNotExist:
        messages.error(request, 'The requested incident does not exist!')
        return render(request, 'kraut_incident/incident_list.html', context)
    try:
        task = Task.objects.get(id=task_id)
    except Task.DoesNotExist:
        messages.error(request, 'The requested task does not exist!')
        return render(request, 'kraut_incident/incident_list.html', context)
    task.status = 'ab'
    task.finish_time = datetime.datetime.now()
    task.save()
    return HttpResponseRedirect(reverse("incidents:view_incident", kwargs={'incident_id': incident_id}))

@login_required
def resolve_task_incident(request, incident_id, task_id):
    """resolve a task from an incident
    """
    context = {}
    try:
        inc = Incident.objects.get(id=incident_id)
    except Incident.DoesNotExist:
        messages.error(request, 'The requested incident does not exist!')
        return render(request, 'kraut_incident/incident_list.html', context)
    try:
        task = Task.objects.get(id=task_id)
    except Task.DoesNotExist:
        messages.error(request, 'The requested task does not exist!')
        return render(request, 'kraut_incident/incident_list.html', context)
    task.status = 'do'
    task.finish_time = datetime.datetime.now()
    task.save()
    return HttpResponseRedirect(reverse("incidents:view_incident", kwargs={'incident_id': incident_id}))

@login_required
def remove_task_incident(request, incident_id, task_id):
    """remove a task from an incident
    """
    context = {}
    try:
        inc = Incident.objects.get(id=incident_id)
    except Incident.DoesNotExist:
        messages.error(request, 'The requested incident does not exist!')
        return render(request, 'kraut_incident/incident_list.html', context)
    try:
        task = Task.objects.get(id=task_id)
    except Task.DoesNotExist:
        messages.error(request, 'The requested task does not exist!')
        return render(request, 'kraut_incident/incident_list.html', context)
    inc.tasks.remove(task)
    inc.save()
    return HttpResponseRedirect(reverse("incidents:view_incident", kwargs={'incident_id': incident_id}))

@login_required
def remove_contact_incident(request, incident_id, contact_id):
    """remove contact person from incident
    """
    context = {}
    try:
        inc = Incident.objects.get(id=incident_id)
    except Incident.DoesNotExist:
        messages.error(request, 'The requested incident does not exist!')
        return render(request, 'kraut_incident/incident_list.html', context)
    try:
        contact = Contact.objects.get(id=contact_id)
    except Handler.DoesNotExist:
        messages.error(request, 'The requested incident contact does not exist!')
        return render(request, 'kraut_incident/incident_list.html', context)
    inc.contacts.remove(contact)
    inc.save()
    return HttpResponseRedirect(reverse("incidents:view_incident", kwargs={'incident_id': incident_id}))

@login_required
def remove_handler_incident(request, incident_id, handler_id):
    """remove handler from incident
    """
    context = {}
    try:
        inc = Incident.objects.get(id=incident_id)
    except Incident.DoesNotExist:
        messages.error(request, 'The requested incident does not exist!')
        return render(request, 'kraut_incident/incident_list.html', context)
    try:
        handler = Handler.objects.get(id=handler_id)
    except Handler.DoesNotExist:
        messages.error(request, 'The requested incident handler does not exist!')
        return render(request, 'kraut_incident/incident_list.html', context)
    inc.incident_handler.remove(handler)
    inc.save()
    return HttpResponseRedirect(reverse("incidents:view_incident", kwargs={'incident_id': incident_id}))

@login_required
def add_contact_incident(request, incident_id):
    """add incident contact to incident
    """
    if request.method == 'POST':
        try:
            inc = Incident.objects.get(id=incident_id)
        except Incident.DoesNotExist:
            messages.error(request, 'The requested incident does not exist!')
            return render(request, 'kraut_incident/incident_list.html', context)
        co_dict = slicedict(request.POST, 'ContactCheckBox')
        for key in co_dict:
            co_id = int(co_dict[key])
            try:
                co = Contact.objects.get(id=co_id)
                inc.contacts.add(co)
            except Contact.DoesNotExist:
                messages.error(request, 'Failed getting incident contact with ID: %s' % (co_id))
                return HttpResponseRedirect(reverse("incidents:view_incident", kwargs={'incident_id': incident_id}))
        inc.save()
    return HttpResponseRedirect(reverse("incidents:view_incident", kwargs={'incident_id': incident_id}))

@login_required
def add_handler_incident(request, incident_id):
    """add incident handler to incident
    """
    if request.method == 'POST':
        try:
            inc = Incident.objects.get(id=incident_id)
        except Incident.DoesNotExist:
            messages.error(request, 'The requested incident does not exist!')
            return render(request, 'kraut_incident/incident_list.html', context)
        handler_dict = slicedict(request.POST, 'HandlerCheckBox')
        for key in handler_dict:
            handler_id = int(handler_dict[key])
            try:
                ih = Handler.objects.get(id=handler_id)
                inc.incident_handler.add(ih)
            except Handler.DoesNotExist:
                messages.error(request, 'Failed getting incident handler with ID: %s' % (handler_id))
                return HttpResponseRedirect(reverse("incidents:view_incident", kwargs={'incident_id': incident_id}))
        inc.save()
    return HttpResponseRedirect(reverse("incidents:view_incident", kwargs={'incident_id': incident_id}))

@login_required
def add_task(request, incident_id):
    """add task to incident
    """
    if request.method == 'POST':
        try:
            inc = Incident.objects.get(id=incident_id)
        except Incident.DoesNotExist:
            messages.error(request, 'The requested incident does not exist!')
            return render(request, 'kraut_incident/incident_list.html', context)
        task_dict = slicedict(request.POST, 'TaskCheckBox')
        for key in task_dict:
            task_id = int(task_dict[key])
            try:
                tt = TemplateTask.objects.get(id=task_id)
                template = {
                    "name": tt.name,
                    "description": tt.description
                }
                t = Task(**template)
                t.save()
                inc.tasks.add(t)
            except:
                messages.error(request, 'Failed getting incident task with ID: %s' % (task_id))
                return HttpResponseRedirect(reverse("incidents:view_incident", kwargs={'incident_id': incident_id}))
        messages.info(request, 'Task "%s" added' % (t.name))
        inc.save()
    return HttpResponseRedirect(reverse("incidents:view_incident", kwargs={'incident_id': incident_id}))

@login_required
def update_incident_header(request, incident_id):
    """Update incident header information
    """
    context = {}
    try:
        inc = Incident.objects.get(id=incident_id)
    except Incident.DoesNotExist:
        messages.error(request, 'The requested incident does not exist!')
        return render(request, 'kraut_incident/incident_list.html', context)
    if request.method == "POST":
        inc_title = request.POST.get('incident_title', None)
        inc_severity = request.POST.get('incident_severity', None)
        inc_descr = request.POST.get('incident_description', None)
        if inc_title:
            inc.title = inc_title
        if inc_severity:
            if inc_severity == 'High': inc_severity = 'h'
            if inc_severity == 'Medium': inc_severity = 'm'
            if inc_severity == 'Low': inc_severity = 'l'
            inc.severity = inc_severity
        if inc_descr:
            inc.description = inc_descr
        inc.save()
    return HttpResponseRedirect(reverse("incidents:view_incident", kwargs={'incident_id': incident_id}))

@login_required
def comment_incident(request, incident_id):
    """Add comment to incident
    """
    context = {}
    if request.method == "POST":
        form = IncidentCommentForm(request.POST)
        if form.is_valid():
            try:
                inc = Incident.objects.get(id=incident_id)
            except Incident.DoesNotExist:
                messages.error(request, 'The requested incident does not exist!')
                return render(request, 'kraut_incident/incident_list.html', context)
            data = {
                'ctext': form.cleaned_data['ctext'],
                'author': request.user,
                'incident_reference': inc
            }
            new_comment = IncidentComment.objects.get_or_create(**data)
            messages.info(request, "Comment successfully added")
        else:
            if form.errors:
                for field in form:
                    for error in field.errors:
                        messages.error(request, '%s: %s' % (field.name, error))
    return HttpResponseRedirect(reverse("incidents:view_incident", kwargs={'incident_id': incident_id}))

@login_required
def delete_comment_incident(request, incident_id, comment_id):
    """Delete a comment for given incident
    """
    context = {}
    try:
        inc = Incident.objects.get(id=incident_id)
    except Incident.DoesNotExist:
        messages.error(request, 'The requested incident does not exist!')
        return render(request, 'kraut_incident/incident_list.html', context)
    try:
        com = IncidentComment.objects.get(pk=int(comment_id), incident_reference=inc, author=request.user)
    except IncidentComment.DoesNotExist:
        messages.error(request, 'The requested comment does not exist!')
        return render(request, 'kraut_incident/incident_list.html', context)
    com.delete()
    messages.info(request, 'Comment successfully deleted.')
    return HttpResponseRedirect(reverse("incidents:view_incident", kwargs={'incident_id': incident_id}))

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
    context['severity'] = inc.get_severity_display()
    if hasattr(request.user.userextension, 'namespaces'):
        context['usernamespace'] = request.user.userextension.namespaces.last().namespace.split(':')[0]
        context['namespaceicon'] = get_icon_for_namespace(request.user.userextension.namespaces.last().namespace)
    else:
        context['usernamespace'] = 'nospace'
        context['namespaceicon'] = static('ns_icon/octalpus.png')
    try:
        comments = IncidentComment.objects.filter(incident_reference=inc).order_by('-creation_time')
    except:
        comments = None
    context['comments'] = comments
    context['commentform'] = IncidentCommentForm()
    context['num_incident_handlers'] = inc.incident_handler.count()
    context['num_incident_contacts'] = inc.contacts.count()
    context['num_incident_tasks'] = inc.tasks.count()
    context['num_affected_assets'] = inc.affected_assets.count()
    if context['num_incident_tasks'] > 0:
        context['tab'] = 'incident_tasks'
    elif context['num_incident_contacts'] > 0:
        context['tab'] = 'incident_contacts'
    else:
        context['tab'] = 'incident_handler'
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
