# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

import datetime, pytz

from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.template import RequestContext
from django.contrib import messages
from django.contrib.auth.decorators import login_required

from kraut_sharing.forms import DiscoveryForm, PollForm, AddServerForm, EditCollectionForm
from kraut_sharing.models import TAXII_Remote_Server, TAXII_Remote_Collection
from kraut_sharing.tasks import refresh_collection_task, poll_collection

# Create your views here.

@login_required
def home(request):
    """ discovery collections available at a TAXII server """
    context = {}
    form = DiscoveryForm()
    context['form'] = form
    context['servers'] = TAXII_Remote_Server.objects.all()
    return render(request, 'kraut_sharing/index.html', context)

@login_required
def manage_osint_feeds(request):
    """ manage OSINT feeds """
    context = {}
    return render(request, 'kraut_sharing/osintfeeds.html', context)


@login_required
def manage_servers(request):
    """ manage taxii servers """
    context = {}
    if not request.method == 'POST':
        serverForm = AddServerForm()
        context['form'] = serverForm
        return render(request, 'kraut_sharing/servers.html', context)
    serverForm = AddServerForm(request.POST)
    if serverForm.is_valid():
        oldID = int(request.POST.get('oldid', 0))
        if oldID == 0:
            new_server = TAXII_Remote_Server.objects.get_or_create(**serverForm.cleaned_data)
            messages.info(request, 'Successfully added new TAXII server!')
        else:
            old_server = TAXII_Remote_Server.objects.filter(id=oldID).update(**serverForm.cleaned_data)
            messages.info(request, 'Successfully updated TAXII server!')
    else:
        if serverForm.errors:
            for field in serverForm:
                for error in field.errors:
                    messages.error(request, '%s: %s' % (field.name, error))
    context['form'] = serverForm
    return HttpResponseRedirect(reverse("sharing:servers"))

@login_required
def delete_server(request, server_id):
    """ delete TAXII server """
    try:
        server = TAXII_Remote_Server.objects.get(pk=int(server_id))
    except TAXII_Remote_Server.DoesNotExist:
        messages.error(request, 'The requested TAXII server does not exist!')
        return HttpResponseRedirect(reverse("sharing:servers"))
    # check for associated collections and delete them as well
    try:
        collections = TAXII_Remote_Collection.objects.filter(server=server)
    except Exception as e:
        print e
        collections = []
    for collection in collections:
        collection.delete()
    # finally delete server
    server.delete()
    messages.info(request, 'The TAXII server was deleted successfully!')
    return HttpResponseRedirect(reverse("sharing:servers"))

@login_required
def list_collections(request):
    """ list all collections """
    context = {}
    if request.method == 'POST':
        oldID = int(request.POST.get('oldid', 0))
        if oldID > 0:
            try:
                collection = TAXII_Remote_Collection.objects.get(id=oldID)
            except TAXII_Remote_Collection.DoesNotExist:
                messages.error(request, "provided collection does not exist!")
                return HttpResponseRedirect(reverse("sharing:collections"))
            collectionForm = EditCollectionForm(request.POST, instance=collection)
            if collectionForm.is_valid():
                collectionForm.save()
                messages.info(request, 'Successfully updated collection!')
            else:
                if collectionForm.errors:
                    for field in collectionForm:
                        for error in field.errors:
                            messages.error(request, '%s: %s' % (field.name, error))
        else:
            messages.error(request, "wrong collection ID provided!")
        return HttpResponseRedirect(reverse("sharing:collections"))
    collectionForm = EditCollectionForm()
    context['form'] = collectionForm
    return render(request, 'kraut_sharing/collections.html', context)

@login_required
def refresh_collection(request, server_id):
    """ refresh list of collections for given server """
    refresh_collection_task(server_id)
    messages.info(request, 'Collection list updated successfully')
    return HttpResponseRedirect(reverse("sharing:servers"))

@login_required
def delete_collection(request, collection_id):
    """ remove given collection from the database """
    try:
        collection = TAXII_Remote_Collection.objects.get(id=collection_id)
    except TAXII_Remote_Collection.DoesNotExist:
        messages.error(request, "provided collection does not exist!")
        return HttpResponseRedirect(reverse("sharing:collections"))
    # TODO: check for subscriptions or poll jobs (cron)
    collname = collection.name
    collection.delete()
    messages.info(request, "collection %s successfully deleted." % (collname))
    return HttpResponseRedirect(reverse("sharing:collections"))

@login_required
def poll_now(request, collection_id):
    """ poll given collection """
    try:
        collection = TAXII_Remote_Collection.objects.get(id=collection_id)
    except TAXII_Remote_Collection.DoesNotExist:
        messages.error(request, "provided collection does not exist!")
        return HttpResponseRedirect(reverse("sharing:collections"))
    try:
        poll_collection.delay(collection)
        messages.info(request, "polling information from: %s ..." % (collection.name))
    except Exception as e:
        messages.error(request, "failed polling collection, check if celery is running")
    return HttpResponseRedirect(reverse("sharing:collections"))

@login_required
def poll(request):
    """ poll collection information """
    context = {}
    # set begin time by default to 24 hours ago
    begin_time = datetime.datetime.now(pytz.utc) - datetime.timedelta(hours = 24)
    if not request.method == 'POST':
        form = PollForm(initial={'begin_time': begin_time.strftime('%Y-%m-%dT%H:%M:%S.%f%z')})
        context['form'] = form
        return render(request, 'kraut_sharing/poll.html', context)
    form = PollForm(initial={'url': request.POST.get('url'), 'service': request.POST.get('service'), 'begin_time': begin_time.strftime('%Y-%m-%dT%H:%M:%S.%f%z')})
    context['form'] = form
    messages.info(request, 'Polling intelligence ...')
    return render(request, 'kraut_sharing/poll.html', context)
