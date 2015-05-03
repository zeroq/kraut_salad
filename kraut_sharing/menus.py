# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.core.urlresolvers import reverse
from menu import Menu, MenuItem

incident_children = (
    MenuItem("Taxii",
            reverse("sharing:home"),
            weight=10,
            image="images/Taxii.svg"),
)

Menu.add_item("sharing", MenuItem("Sharing",
    reverse("sharing:home"),
    weight=10,
    children=incident_children)
)
