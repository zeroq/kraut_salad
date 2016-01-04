# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django import forms
from django.forms import ModelForm, widgets

from kraut_sharing.models import TAXII_Remote_Server, TAXII_Remote_Collection

forms.DateInput.input_type="datetime"

class DiscoveryForm(forms.Form):
    url = forms.URLField(label='Discovery URL', max_length='255', widget=forms.TextInput(attrs={'class': 'form-control', 'id': 'discoveryURL', 'name': 'discoveryURL'}))


class PollForm(forms.Form):
    url = forms.URLField(label='URL', max_length='255', widget=forms.TextInput(attrs={'class': 'form-control', 'id': 'URL'}))
    service = forms.CharField(label='Feed Name', max_length='255', widget=forms.TextInput(attrs={'class': 'form-control', 'id': 'feed'}))
    begin_time = forms.DateTimeField(label='Begin timestamp', widget=forms.DateTimeInput(attrs={'class':'form-control', 'id': 'begin'}), required=False)
    end_time = forms.DateTimeField(label='End timestamp', widget=forms.DateTimeInput(attrs={'class':'form-control', 'id': 'end', 'placeholder': 'None'}), required=False)
    poll_choices = (
        ('0', 'only once'),
        ('1', 'every hour'),
        ('8', 'every 8 hours'),
        ('24', 'every 24 hours'),
    )
    poll = forms.ChoiceField(label='Poll periodically', widget=forms.Select(attrs={'class': 'form-control', 'id': 'polling'}), choices=poll_choices)

class AddServerForm(ModelForm):
    class Meta:
        model = TAXII_Remote_Server
        fields = ['name', 'host', 'path', 'port', 'protocol', 'version']
        widgets = {
            'name': widgets.TextInput(attrs={'id': 'post_server_name', 'class': 'form-control', 'placeholder': ''}),
            'host': widgets.TextInput(attrs={'id': 'post_server_host', 'class': 'form-control', 'placeholder': ''}),
            'port': widgets.NumberInput(attrs={'id': 'post_server_port', 'class': 'form-control', 'placeholder': '', 'readonly': True, 'required': True}),
            'path': widgets.TextInput(attrs={'id': 'post_server_path', 'class': 'form-control', 'placeholder': ''}),
            'version': widgets.TextInput(attrs={'id': 'post_server_version', 'class': 'form-control', 'placeholder': '', 'readonly': True, 'required': True}),
            'protocol': widgets.TextInput(attrs={'id': 'post_server_protocol', 'class': 'form-control', 'placeholder': '', 'readonly': True, 'required': True}),
        }

class AddCollectionForm(ModelForm):
    class Meta:
        model = TAXII_Remote_Collection
        fields = ['name', 'begin_timestamp', 'poll_period']
        widgets = {
            'name': widgets.TextInput(attrs={'id': 'post_collection_name', 'class': 'form-control', 'placeholder': ''}),
            'begin_timestamp': widgets.DateTimeInput(attrs={'id': 'post_begin_time', 'class': 'form-control', 'placeholder': ''}),
            'period': widgets.NumberInput(attrs={'id': 'post_poll_period', 'class': 'form-control', 'placeholder': ''}),
        }
