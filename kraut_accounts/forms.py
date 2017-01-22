# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.forms import PasswordInput, CharField, Form

class PasswordChangeCustomForm(Form):
    old_password = CharField(required=True, label="Old Password", widget=PasswordInput(attrs={'class': 'form-control'}))
    new_password1 = CharField(required=True, label="New Password", widget=PasswordInput(attrs={'class': 'form-control'}))
    new_password2 = CharField(required=True, label="Repeat New Password", widget=PasswordInput(attrs={'class': 'form-control'}))
