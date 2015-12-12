from django.forms import ModelForm

from kraut_parser.models import Package

class PackageForm(ModelForm):
    class Meta:
        model = Package
        fields = ['name', 'description', 'short_description', 'namespace', 'version', 'package_id', 'source', 'produced_time']

    def __init__(self, *args, **kwargs):
        super(PackageForm, self).__init__(*args, **kwargs)
        self.fields['name'].widget.attrs.update({'class' : 'form-control', 'id': 'packageName'})
        self.fields['namespace'].widget.attrs.update({'class' : 'form-control', 'id': 'nameSpace'})
        self.fields['produced_time'].widget.attrs.update({'class' : 'form-control', 'id': 'producedTime'})
        self.fields['version'].widget.attrs.update({'class' : 'form-control', 'id': 'version'})
        self.fields['source'].widget.attrs.update({'class' : 'form-control', 'id': 'source'})
        self.fields['description'].widget.attrs.update({'class' : 'form-control', 'id': 'description'})
        self.fields['short_description'].widget.attrs.update({'class' : 'form-control', 'id': 'shortDescription'})
        self.fields['package_id'].widget.attrs.update({'class' : 'form-control', 'id': 'packageID'})
