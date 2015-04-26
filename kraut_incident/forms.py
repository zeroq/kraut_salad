# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.forms import ModelForm, widgets
from kraut_incident.models import Incident

class IncidentForm(ModelForm):
    class Meta:
        model = Incident
        fields = ['incident_number', 'title', 'description', 'status', 'category']
        widgets = {
            'incident_number': widgets.NumberInput(attrs={'class': 'form-control', 'readonly': True}),
            'title': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': 'Provide a name for the incident or investigation'}),
            'description': widgets.Textarea(attrs={'class': 'form-control', 'placeholder': 'What and when did it happened ...'}),
            'status': widgets.Select(attrs={'class': 'form-control'}),
            'category': widgets.Select(attrs={'class': 'form-control'}),
        }
