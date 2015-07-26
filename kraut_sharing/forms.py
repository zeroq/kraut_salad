# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django import forms

class DiscoveryForm(forms.Form):
    url = forms.URLField(label='Discovery URL', max_length='255', widget=forms.TextInput(attrs={'class': 'form-control', 'id': 'discoveryURL', 'placeholder': 'http://hailataxii.com/services/discovery'}))
