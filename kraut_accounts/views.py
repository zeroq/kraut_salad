from django.shortcuts import render_to_response
from django.contrib.auth import authenticate, login, logout, update_session_auth_hash
from django.contrib.auth.hashers import check_password
from django.http import HttpResponseRedirect
from django.core.urlresolvers import reverse
from django.template import RequestContext
from django.contrib import messages

from kraut_accounts.models import UserExtension
from kraut_accounts.forms import PasswordChangeCustomForm
from kraut_parser.models import Namespace

from kraut_intel.utils import get_icon_for_namespace

# Create your views here.

def accounts_change_password(request):
    """change password
    """
    if request.method == 'POST':
        form = PasswordChangeCustomForm(request.POST)
        if form.is_valid():
            current_user = request.user
            # check if old password equals current password
            old_pass = form.cleaned_data['old_password']
            n1_pass = form.cleaned_data['new_password1']
            n2_pass = form.cleaned_data['new_password2']
            if not current_user.check_password(old_pass):
                messages.error(request, 'Old password wrong!')
                return HttpResponseRedirect(reverse("accounts:changepw"))
            if n1_pass != n2_pass:
                messages.error(request, 'New password does not match!')
                return HttpResponseRedirect(reverse("accounts:changepw"))
            # change password
            current_user.set_password(n1_pass)
            update_session_auth_hash(request, request.user)
            current_user.save()
            messages.info(request, 'Password successfully changed!')
        else:
            messages.error(request, 'Failure updating password!')
        return HttpResponseRedirect(reverse("accounts:changepw"))
    context = {'form': PasswordChangeCustomForm()}
    if hasattr(request.user.userextension, 'namespaces'):
        context['usernamespace'] = request.user.userextension.namespaces.last().namespace.split(':')[0]
        context['namespaceicon'] = get_icon_for_namespace(request.user.userextension.namespaces.last().namespace)
    else:
        context['usernamespace'] = 'nospace'
        context['namespaceicon'] = static('ns_icon/octalpus.png')
    return render_to_response('kraut_accounts/changepw.html', context, context_instance=RequestContext(request))


def accounts_login(request):
    """log a user in
    """
    context = {}
    if request.user.is_authenticated():
        return HttpResponseRedirect(reverse("home"))
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(username=username, password=password)
        if user is not None:
            if user.is_active:
                if not hasattr(user, 'userextension'):
                    user_extension = UserExtension.objects.create(user=user)
                    user_extension.save()
                    new_namespace = Namespace(namespace='nospace:http://nospace.com', description='no particular namespace')
                    new_namespace.save()
                    user_extension.namespaces.add(new_namespace)
                    user_extension.save()
                login(request, user)
                return HttpResponseRedirect(request.POST.get('next',reverse('home')))
            else:
                messages.error(request, '%s: is not activated!' % (username))
        else:
            messages.error(request, 'Logon failed!')
        return HttpResponseRedirect(reverse("accounts:login"))
    return render_to_response('kraut_accounts/login.html', context, context_instance=RequestContext(request))


def accounts_logout(request):
    """log a user out
    """
    logout(request)
    messages.info(request, 'Successfully logged out.')
    return HttpResponseRedirect(reverse("accounts:login"))
