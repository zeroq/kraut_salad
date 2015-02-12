# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

import django_tables2 as tables

from kraut_parser.models import Package

class PackageTable(tables.Table):
    name = tables.TemplateColumn(verbose_name="package name", template_name='kraut_intel/package_name_column.html')
    operations = tables.TemplateColumn(template_name='kraut_intel/operations_column.html', orderable=False)

    class Meta:
        model = Package
        order_by = ("-last_modified")
        sequence = ("name", "short_description", "last_modified")
        exclude = ("id", "creation_time", "description", "namespace", "version", "package_id", "source", "produced_time")
        attrs = {"class": "table table-condensed table-hover"}
