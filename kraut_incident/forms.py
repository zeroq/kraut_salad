# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.forms import ModelForm, widgets
from kraut_incident.models import Incident, Contact, Handler, IncidentComment

class HandlerForm(ModelForm):
    class Meta:
        model = Handler
        fields = ["firstname", "lastname", "phone", "email", "description"]
        widgets = {
            'firstname': widgets.TextInput(attrs={'id': 'post_handler_firstname', 'class': 'form-control', 'placeholder': ''}),
            'lastname': widgets.TextInput(attrs={'id': 'post_handler_lastname', 'class': 'form-control', 'placeholder': ''}),
            'phone': widgets.TextInput(attrs={'id': 'post_handler_phone', 'class': 'form-control', 'placeholder': ''}),
            'email': widgets.EmailInput(attrs={'id': 'post_handler_email', 'class': 'form-control', 'placeholder': ''}),
            'description': widgets.Textarea(attrs={'id': 'post_handler_description', 'class': 'form-control', 'placeholder': 'What is this handler responsible for ...'}),
        }

class ContactForm(ModelForm):
    class Meta:
        model = Contact
        fields = ["firstname", "lastname", "phone", "email", "description"]
        widgets = {
            'firstname': widgets.TextInput(attrs={'id': 'post_contact_firstname', 'class': 'form-control', 'placeholder': ''}),
            'lastname': widgets.TextInput(attrs={'id': 'post_contact_lastname', 'class': 'form-control', 'placeholder': ''}),
            'phone': widgets.TextInput(attrs={'id': 'post_contact_phone', 'class': 'form-control', 'placeholder': ''}),
            'email': widgets.EmailInput(attrs={'id': 'post_contact_email', 'class': 'form-control', 'placeholder': ''}),
            'description': widgets.Textarea(attrs={'id': 'post_contact_description', 'class': 'form-control', 'placeholder': 'What is this contact responsible for ...'}),
        }


class IncidentForm(ModelForm):
    class Meta:
        model = Incident
        fields = ['incident_number', 'title', 'description', 'status', 'category', 'severity']
        widgets = {
            'incident_number': widgets.NumberInput(attrs={'class': 'form-control', 'readonly': True, 'required': True}),
            'title': widgets.TextInput(attrs={'class': 'form-control', 'placeholder': 'Provide a name for the incident or investigation', 'required': True}),
            'description': widgets.Textarea(attrs={'class': 'form-control', 'placeholder': 'What and when did it happened ...'}),
            'status': widgets.Select(attrs={'class': 'form-control'}),
            'category': widgets.Select(attrs={'class': 'form-control'}),
            'severity': widgets.Select(attrs={'class': 'form-control'}),
        }

class IncidentCommentForm(ModelForm):
    class Meta:
        model = IncidentComment
        fields = ['ctext']

    def __init__(self, *args, **kwargs):
        super(IncidentCommentForm, self).__init__(*args, **kwargs)
        self.fields['ctext'].widget.attrs.update({'class' : 'form-control', 'id': 'incidentComment'})
