# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.http import HttpResponse
from rest_framework import status
from django.db.models import Prefetch, Q
from django.shortcuts import render
from django.contrib.auth.decorators import login_required

from kraut_parser.models import Observable, File_Object

# Create your views here.

@login_required
def base_search(request):
    context = {'sterm': None, 'result': []}
    if not request.method == 'POST':
        return HttpResponse(status=status.HTTP_400_BAD_REQUEST)
    sterm = request.POST.get('searchbar', None)
    context['sterm'] = sterm
    ### search file objects
    queryset = Observable.objects.filter(
        Q(file_object__md5_hash=sterm)|
        Q(file_object__sha256_hash=sterm)|
        Q(file_object__file_meta__file_name=sterm)
    ).order_by('-last_modified')
    for item in queryset:
        context['result'].append( (item.name, item.observable_type) )
    ### search domain objects
    return render(request, 'kraut_search/index.html', context)
