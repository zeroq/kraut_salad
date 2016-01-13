from django.shortcuts import render_to_response
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.template import RequestContext
from django.contrib import messages

from kraut_accounts.models import UserExtension

# Create your views here.

def accounts_login(request):
    """ log a user in """
    context = {}
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                if not hasattr(user, 'userextension'):
                    UserExtension.objects.create(user=user)
                login(request, user)
                return HttpResponseRedirect(request.POST.get('next',reverse('home')))
            else:
                messages.error(request, '%s: is not activated!' % (username))
        else:
            messages.error(request, 'Logon failed!')
        return HttpResponseRedirect(reverse("accounts:login"))
    return render_to_response('kraut_accounts/login.html', context, context_instance=RequestContext(request))


def accounts_logout(request):
    """ log a user out """
    logout(request)
    messages.info(request, 'Successfully logged out.')
    return HttpResponseRedirect(reverse("accounts:login"))
