# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.db import models

# Create your models here.

class Namespace(models.Model):
    namespace = models.CharField(max_length=255, default='nospace', unique=True)
    description = models.TextField(null=True, blank=True)

    def __unicode__(self):
        return u"%s" % (self.namespace)

    class Meta:
        ordering = ['namespace']

class Confidence(models.Model):
    value = models.CharField(max_length=255)
    description = models.TextField(null=True, blank=True)

    def __unicode__(self):
        return u"%s" % (self.value)

class Package(models.Model):
    name = models.CharField(max_length=255)
    creation_time = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    description = models.TextField(null=True, blank=True)
    short_description = models.CharField(max_length=255, null=True, blank=True)
    namespace = models.ManyToManyField('Namespace', blank=True)
    version = models.CharField(max_length=255)
    package_id = models.CharField(max_length=255)
    source = models.CharField(max_length=255)
    produced_time = models.DateTimeField(null=True, blank=True)
    threat_actors = models.ManyToManyField('ThreatActor', blank=True)
    campaigns = models.ManyToManyField('Campaign', blank=True)
    indicators = models.ManyToManyField('Indicator', blank=True)
    observables = models.ManyToManyField('Observable', blank=True)
    ttps = models.ManyToManyField('TTP', blank=True)

    def __unicode__(self):
        return u"%s" % (self.name)

class Package_Intent(models.Model):
    intent = models.CharField(max_length=255)
    package = models.ForeignKey(Package)

    def __unicode__(self):
        return u"%s" % (self.intent)

class Package_Reference(models.Model):
    reference = models.CharField(max_length=1024)
    package = models.ForeignKey(Package)

    def __unicode__(self):
        return u"%s" % (self.reference)

class TTP(models.Model):
    """ Tools, Tactics, and Procedures
    """
    name = models.CharField(max_length=255)
    creation_time = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    description = models.TextField(null=True, blank=True)
    short_description = models.CharField(max_length=255, null=True, blank=True)
    namespace = models.ManyToManyField('Namespace', blank=True)
    ttp_id = models.CharField(max_length=255)
    related_ttps = models.ManyToManyField('self', through='RelatedTTP', symmetrical=False, related_name='ttp_related_to_ttp', blank=True)

    def add_related_ttp(self, ttp, relationship):
        rel_ttp, rel_ttp_created = RelatedTTP.objects.get_or_create(from_ttp=self, to_ttp=ttp, relationship=relationship)
        return rel_ttp

    def __unicode__(self):
        return u"%s" % (self.name)

class RelatedTTP(models.Model):
    from_ttp = models.ForeignKey(TTP, related_name='from_ttp')
    to_ttp = models.ForeignKey(TTP, related_name='to_ttp')
    relationship = models.CharField(max_length=255)

class MalwareInstance(models.Model):
    ttp_ref = models.ForeignKey(TTP)
    name = models.CharField(max_length=255)
    creation_time = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    description = models.TextField(null=True, blank=True)
    short_description = models.CharField(max_length=255, null=True, blank=True)

    def __unicode__(self):
        return u"%s" % (self.name)

class MalwareInstanceNames(models.Model):
    instance_ref = models.ForeignKey(MalwareInstance)
    name = models.CharField(max_length=255)

    def __unicode__(self):
        return u"%s" % (self.name)

class MalwareInstanceTypes(models.Model):
    instance_ref = models.ForeignKey(MalwareInstance)
    _type = models.CharField(max_length=255)

    def __unicode__(self):
        return u"%s" % (self._type)

class AttackPattern(models.Model):
    ttp_ref = models.ForeignKey(TTP)
    name = models.CharField(max_length=255)
    creation_time = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    description = models.TextField(null=True, blank=True)
    short_description = models.CharField(max_length=255, null=True, blank=True)
    capec_id = models.CharField(max_length=255)


class Campaign(models.Model):
    name = models.CharField(max_length=255)
    creation_time = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    description = models.TextField(null=True, blank=True)
    short_description = models.CharField(max_length=255, null=True, blank=True)
    namespace = models.ManyToManyField('Namespace', blank=True)
    status = models.CharField(max_length=255, default='Ongoing')
    campaign_id = models.CharField(max_length=255)
    confidence = models.ManyToManyField(Confidence, blank=True)
    related_indicators = models.ManyToManyField('Indicator', blank=True)
    related_ttps = models.ManyToManyField(TTP, through='RelationCampaignTTP', symmetrical=False, related_name='ttp_related_to_campaign', blank=True)
    associated_campaigns = models.ManyToManyField('self', blank=True)

    def add_related_ttp(self, ttp, relationship):
        rel_ttp, rel_ttp_created = RelationCampaignTTP.objects.get_or_create(
            campaign=self,
            ttp=ttp,
            relationship=relationship
        )
        return rel_ttp

    def __unicode__(self):
        return u"%s" % (self.name)

class RelationCampaignTTP(models.Model):
    campaign = models.ForeignKey(Campaign)
    ttp = models.ForeignKey(TTP)
    relationship = models.CharField(max_length=255)

class ThreatActor(models.Model):
    name = models.CharField(max_length=255)
    creation_time = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    description = models.TextField(null=True, blank=True)
    short_description = models.CharField(max_length=255, null=True, blank=True)
    namespace = models.ManyToManyField('Namespace', blank=True)
    campaigns = models.ManyToManyField(Campaign, blank=True)
    associated_threat_actors = models.ManyToManyField('self', blank=True)
    threat_actor_id = models.CharField(max_length=255)
    observed_ttps = models.ManyToManyField(TTP, through='ObservedTTP', symmetrical=False, related_name='ttp_observed_at_ta', blank=True)

    def add_observed_ttp(self, ttp, relationship):
        obs_ttp, obs_ttp_created = ObservedTTP.objects.get_or_create(
            ta=self,
            ttp=ttp,
            relationship=relationship
        )
        return obs_ttp

    def __unicode__(self):
        return u"%s" % (self.name)

class ObservedTTP(models.Model):
    ta = models.ForeignKey(ThreatActor)
    ttp = models.ForeignKey(TTP)
    relationship = models.CharField(max_length=255)

class TA_Types(models.Model):
    ta_type = models.CharField(max_length=255)
    actor = models.ForeignKey(ThreatActor)

    def __unicode__(self):
        return u"%s" % (self.ta_type)

    class Meta:
        unique_together = (("ta_type", "actor"),)

class TA_Roles(models.Model):
    role = models.CharField(max_length=255)
    actor = models.ForeignKey(ThreatActor)

    def __unicode__(self):
        return u"%s" % (self.role)

    class Meta:
        unique_together = (("role", "actor"),)

class TA_Alias(models.Model):
    alias = models.CharField(max_length=255)
    namespace = models.ManyToManyField('Namespace', blank=True)
    actor = models.ForeignKey(ThreatActor)
    alias_type = models.CharField(max_length=255, default='UnofficialName')

    def __unicode__(self):
        return u"%s" % (self.alias)

    class Meta:
        unique_together = (("alias", "actor"),)

class Indicator_Kill_Chain_Phase(models.Model):
    name = models.CharField(max_length=255, unique=True)
    ordinality = models.IntegerField(null=True, blank=True)

    def __unicode__(self):
        return u"%s" % (self.name)

class Indicator_Type(models.Model):
    itype = models.CharField(max_length=255, unique=True)

    def __unicode__(self):
        return u"%s" % (self.itype)

class Indicator(models.Model):
    name = models.CharField(max_length=255)
    creation_time = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    description = models.TextField(null=True, blank=True)
    short_description = models.CharField(max_length=255, null=True, blank=True)
    indicator_id = models.CharField(max_length=255)
    namespace = models.ManyToManyField('Namespace', blank=True)
    indicator_types = models.ManyToManyField(Indicator_Type, blank=True)
    confidence = models.ManyToManyField(Confidence, blank=True)
    related_indicators = models.ManyToManyField('self', blank=True)
    indicator_composition_operator = models.CharField(max_length=3, default="OR")
    ttps = models.ManyToManyField('TTP', blank=True)
    produced_time = models.DateTimeField(null=True, blank=True)
    kill_chain_phases = models.ManyToManyField(Indicator_Kill_Chain_Phase, blank=True)

    def __unicode__(self):
        return u"%s" % (self.name)

class ObservableComposition(models.Model):
    name = models.CharField(max_length=255)
    operator = models.CharField(max_length=3, default='OR')
    indicator = models.ManyToManyField(Indicator, blank=True)
    observables = models.ManyToManyField('Observable', blank=True)
    observable_compositions = models.ManyToManyField('self', blank=True)

    def __unicode__(self):
        return u"%s" % (self.name)

class Observable(models.Model):
    name = models.CharField(max_length=255)
    creation_time = models.DateTimeField(auto_now_add=True)
    last_modified = models.DateTimeField(auto_now=True)
    description = models.TextField(null=True, blank=True)
    short_description = models.CharField(max_length=255, null=True, blank=True)
    namespace = models.ManyToManyField('Namespace', blank=True)
    indicators = models.ManyToManyField(Indicator, blank=True)
    compositions = models.ManyToManyField(ObservableComposition, blank=True)
    observable_type = models.CharField(max_length=255, null=True, blank=True)
    observable_id = models.CharField(max_length=255, unique=True)

    def __unicode__(self):
        return u"%s" % (self.name)

# Objects

class Related_Object(models.Model):
    relationship = models.CharField(max_length=255, default='contains')
    object_one_id = models.IntegerField()
    object_one_type = models.CharField(max_length=255)
    object_two_id = models.IntegerField()
    object_two_type = models.CharField(max_length=255)

    def __unicode__(self):
        return u"%s:%s -> %s:%s" % (self.object_one_id, self.object_one_type, self.object_two_id, self.object_two_type)

    class Meta:
        unique_together = (("relationship", "object_one_id", "object_two_id", "object_one_type", "object_two_type"),)
        index_together = (("object_one_id", "object_one_type"), ("object_two_id", "object_two_type"))

class File_Custom_Properties(models.Model):
    property_name = models.CharField(max_length=255, null=True, blank=True)
    property_value = models.CharField(max_length=255, null=True, blank=True)

    def __unicode__(self):
        return u"%s - %s" % (self.property_name, self.property_value)

    class Meta:
        unique_together = (("property_name", "property_value"),)

class File_Meta_Object(models.Model):
    file_name = models.CharField(max_length=255, null=True, blank=True)
    file_path = models.CharField(max_length=255, null=True, blank=True)
    file_extension = models.CharField(max_length=255, null=True, blank=True)
    file_size = models.IntegerField(default=0)

    def __unicode__(self):
        if self.file_name:
            return u"%s" % (self.file_name)
        else:
            return u"File Meta Object"

    class Meta:
        unique_together = (("file_name", "file_path", "file_extension", "file_size"),)

class File_Object(models.Model):
    file_meta = models.ManyToManyField(File_Meta_Object, blank=True)
    file_custom = models.ManyToManyField(File_Custom_Properties, blank=True)
    md5_hash = models.CharField(max_length=32, null=True, blank=True)
    sha256_hash = models.CharField(max_length=64, null=True, blank=True)
    observables = models.ManyToManyField(Observable)

    def __unicode__(self):
        if self.md5_hash:
            return u"%s" % (self.md5_hash)
        elif self.sha256_hash:
            return u"%s" % (self.sha256_hash)
        else:
            return u"File Object"

    class Meta:
        index_together = (("md5_hash", "sha256_hash"),)

class URI_Object(models.Model):
    uri_value = models.CharField(max_length=255)
    uri_type = models.CharField(max_length=255)
    condition = models.CharField(max_length=255, default="equals")
    observables = models.ManyToManyField(Observable)

    def __unicode__(self):
        if self.uri_value:
            return u"%s" % (self.uri_value)
        else:
            return u"URI Object"

    class Meta:
        unique_together = (("uri_value", "uri_type", "condition"),)

class Address_Object(models.Model):
    address_value = models.CharField(max_length=255)
    category = models.CharField(max_length=255, default="ipv4-addr")
    condition = models.CharField(max_length=255, default="equals")
    observables = models.ManyToManyField(Observable)

    def __unicode__(self):
        if self.address_value:
            return u"%s" % (self.address_value)
        else:
            return u"Address Object"

    class Meta:
        unique_together = (("address_value", "category", "condition"),)

class Mutex_Object(models.Model):
    mutex_name = models.CharField(max_length=255)
    condition = models.CharField(max_length=255, default="equals")
    observables = models.ManyToManyField(Observable)

    def __unicode__(self):
        if self.mutex_name:
            return u"%s" % (self.mutex_name)
        else:
            return u"Mutex Object"

    class Meta:
        unique_together = (("mutex_name", "condition"),)

class Driver_Object(models.Model):
    driver_name = models.CharField(max_length=255)
    condition = models.CharField(max_length=255, default="contains")
    observables = models.ManyToManyField(Observable)

    def __unicode__(self):
        if self.driver_name:
            return u"%s" % (self.driver_name)
        else:
            return u"Driver Object"

    class Meta:
        unique_together = (("driver_name", "condition"),)

class Win_Registry_Object(models.Model):
    key = models.CharField(max_length=1024)
    hive = models.CharField(max_length=255)
    data = models.CharField(max_length=1024)
    data_name = models.CharField(max_length=255)
    observables = models.ManyToManyField(Observable)

    def __unicode__(self):
        if self.key and self.hive:
            return u"%s - %s" % (self.hive, self.key)
        elif self.key:
            return u"%s" % (self.key)
        else:
            return u"Registry Observable"

    class Meta:
        unique_together = (("key", "hive", "data", "data_name"),)

class Link_Object(models.Model):
    link = models.CharField(max_length=1024)
    link_type = models.CharField(max_length=255)
    url_label = models.CharField(max_length=1024)
    condition = models.CharField(max_length=255, default="contains")
    observables = models.ManyToManyField(Observable)

    def __unicode__(self):
        if self.link:
            return u"%s" % (self.link)
        elif self.url_label:
            return u"%s" % (self.url_label)
        else:
            return u"Link Object"

    class Meta:
        unique_together = (("link", "url_label", "condition", "link_type"),)

class Code_Object(models.Model):
    custom_value = models.CharField(max_length=255)
    custom_condition = models.CharField(max_length=255, default="equals")
    purpose = models.CharField(max_length=255, null=True, blank=True)
    code_language = models.CharField(max_length=255, null=True, blank=True)
    code_segment = models.TextField(null=True, blank=True)
    observables = models.ManyToManyField(Observable)

    def __unicode__(self):
        if self.custom_value:
            return u"%s" % (self.custom_value)
        else:
            return u"Code Object"

    class Meta:
        unique_together = (("custom_value", "custom_condition"),)

class EmailMessage_recipient(models.Model):
    recipient = models.CharField(max_length=255, unique=True)
    is_spoofed = models.BooleanField(default=False)
    condition = models.CharField(max_length=255, default="equals")

class EmailMessage_recipient_cc(models.Model):
    recipient = models.CharField(max_length=255, unique=True)
    is_spoofed = models.BooleanField(default=False)
    condition = models.CharField(max_length=255, default="equals")

class EmailMessage_recipient_bcc(models.Model):
    recipient = models.CharField(max_length=255, unique=True)
    is_spoofed = models.BooleanField(default=False)
    condition = models.CharField(max_length=255, default="equals")

class EmailMessage_sender(models.Model):
    sender = models.CharField(max_length=255, unique=True)
    is_spoofed = models.BooleanField(default=False)
    condition = models.CharField(max_length=255, default="equals")

class EmailMessage_from(models.Model):
    sender = models.CharField(max_length=255, unique=True)
    is_spoofed = models.BooleanField(default=False)
    condition = models.CharField(max_length=255, default="equals")

class EmailMessage_link(models.Model):
    url = models.CharField(max_length=255, unique=True)

class EmailMessage_Object(models.Model):
    raw_body = models.TextField(null=True, blank=True)
    raw_header = models.TextField(null=True, blank=True)
    subject = models.CharField(max_length=255, null=True, blank=True)
    sender = models.ManyToManyField(EmailMessage_sender, blank=True)
    from_string = models.ManyToManyField(EmailMessage_from, blank=True)
    recipients = models.ManyToManyField(EmailMessage_recipient, blank=True)
    recipients_cc = models.ManyToManyField(EmailMessage_recipient_cc, blank=True)
    recipients_bcc = models.ManyToManyField(EmailMessage_recipient_bcc, blank=True)
    links = models.ManyToManyField(EmailMessage_link, blank=True)
    attachments = models.ManyToManyField(File_Object, blank=True)
    email_date = models.DateTimeField(null=True, blank=True)
    message_id = models.CharField(max_length=255, null=True, blank=True)
    content_type = models.CharField(max_length=255, null=True, blank=True)
    mime_version = models.CharField(max_length=255, null=True, blank=True)
    user_agent = models.CharField(max_length=255, null=True, blank=True)
    x_mailer = models.CharField(max_length=255, null=True, blank=True)
    observables = models.ManyToManyField(Observable)

    def __unicode__(self):
        if self.subject:
            return u"%s" % (self.subject)
        else:
            return u"EmailMessage Object"

    class Meta:
        unique_together = (("raw_body", "raw_header", "subject", "message_id", "x_mailer", "user_agent", "mime_version", "content_type", "email_date"),)

class Port_Object(models.Model):
    port = models.IntegerField(unique=True)

    def __unicode__(self):
        return u"%s" % (self.port)

class HTTPClientRequest(models.Model):
    raw_header = models.TextField(null=True, blank=True)
    message_body = models.TextField(null=True, blank=True)
    request_method = models.CharField(max_length=10, null=True, blank=True)
    request_uri = models.CharField(max_length=1024, null=True, blank=True)
    request_version = models.CharField(max_length=10, null=True, blank=True)
    user_agent = models.CharField(max_length=255, null=True, blank=True)
    domain_name = models.ForeignKey(URI_Object, null=True, blank=True)
    port = models.ForeignKey(Port_Object, null=True, blank=True)

    def __unicode__(self):
        if self.request_uri and self.domain_name:
            return u"%s" % (self.request_uri)
        else:
            return u"HTTPClientRequest Object"

class HTTPSession_Object(models.Model):
    client_request = models.ForeignKey(HTTPClientRequest, null=True, blank=True)
    # http server response not implemented
    observables = models.ManyToManyField(Observable)


class DNSQuestion(models.Model):
    qname = models.ForeignKey(URI_Object)
    qtype = models.CharField(max_length=255, null=True, blank=True)
    qclass = models.CharField(max_length=255, null=True, blank=True)

    def __unicode__(self):
        return u"%s" % (self.qname.uri_value)

class DNSQuery_Object(models.Model):
    successful = models.BooleanField(default=False)
    question = models.ForeignKey(DNSQuestion)
    observables = models.ManyToManyField(Observable)

class ImportedFunction(models.Model):
    function_name = models.CharField(max_length=255)
    virtual_address = models.CharField(max_length=255, null=True, blank=True)

class PEImports(models.Model):
    file_name = models.CharField(max_length=255)
    virtual_address = models.CharField(max_length=255, null=True, blank=True)
    imported_functions = models.ManyToManyField(ImportedFunction)

class ExportedFunction(models.Model):
    function_name = models.CharField(max_length=255)
    entry_point = models.CharField(max_length=255, null=True, blank=True)

class PEExports(models.Model):
    name = models.CharField(max_length=255)
    exported_functions = models.ManyToManyField(ExportedFunction)

class PESections(models.Model):
    section_name = models.CharField(max_length=255)
    entropy = models.FloatField(null=True, blank=True)
    virtual_size = models.CharField(max_length=255, null=True, blank=True)
    virtual_address = models.CharField(max_length=255, null=True, blank=True)
    size_of_raw_data = models.CharField(max_length=255, null=True, blank=True)

class WindowsExecutable_Object(models.Model):
    pe_type = models.CharField(max_length=255, default="executable")
    object_id = models.CharField(max_length=255)
    imports = models.ManyToManyField(PEImports)
    exports = models.ManyToManyField(PEExports)
    sections = models.ManyToManyField(PESections)
    observables = models.ManyToManyField(Observable)
