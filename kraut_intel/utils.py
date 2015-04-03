# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.templatetags.static import static

from kraut_intel.models import NamespaceIcon

def get_icon_for_namespace(namespace):
    """ Return the static path to the icon associated with given namespace
    """
    try:
        icon = NamespaceIcon.objects.get(namespace=namespace)
    except:
        return static('ns_icon/octalpus.png')
    return static('ns_icon/%s' % (icon.icon))
