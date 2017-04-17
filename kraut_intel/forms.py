from django.forms import ModelForm

from kraut_parser.models import Package, ThreatActor
from kraut_intel.models import PackageComment, ThreatActorComment, CampaignComment

################### PACKAGE #####################

class PackageCommentForm(ModelForm):
    class Meta:
        model = PackageComment
        fields = ['ctext']

    def __init__(self, *args, **kwargs):
        super(PackageCommentForm, self).__init__(*args, **kwargs)
        self.fields['ctext'].widget.attrs.update({'class' : 'form-control', 'id': 'packageComment'})


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
        self.fields['namespace'].required = True

################### THREAT ACTOR #####################

class ActorCommentForm(ModelForm):
    class Meta:
        model = ThreatActorComment
        fields = ['ctext']

    def __init__(self, *args, **kwargs):
        super(ActorCommentForm, self).__init__(*args, **kwargs)
        self.fields['ctext'].widget.attrs.update({'class' : 'form-control', 'id': 'packageComment'})

class ActorForm(ModelForm):
    class Meta:
        model = ThreatActor
        fields = ['name', 'description', 'short_description', 'namespace', 'threat_actor_id', 'associated_threat_actors']

    def __init__(self, *args, **kwargs):
        super(ActorForm, self).__init__(*args, **kwargs)
        self.fields['name'].widget.attrs.update({'class' : 'form-control', 'id': 'packageName'})
        self.fields['namespace'].widget.attrs.update({'class' : 'form-control', 'id': 'nameSpace'})
        self.fields['description'].widget.attrs.update({'class' : 'form-control', 'id': 'description'})
        self.fields['short_description'].widget.attrs.update({'class' : 'form-control', 'id': 'shortDescription'})
        self.fields['threat_actor_id'].widget.attrs.update({'class' : 'form-control', 'id': 'packageID'})
        self.fields['associated_threat_actors'].widget.attrs.update({'class' : 'form-control', 'id': 'nameSpace'})
        self.fields['namespace'].required = True

################### CAMPAIGN #####################

class CampaignCommentForm(ModelForm):
    class Meta:
        model = CampaignComment
        fields = ['ctext']

    def __init__(self, *args, **kwargs):
        super(CampaignCommentForm, self).__init__(*args, **kwargs)
        self.fields['ctext'].widget.attrs.update({'class' : 'form-control', 'id': 'packageComment'})
