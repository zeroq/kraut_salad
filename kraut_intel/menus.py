# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.core.urlresolvers import reverse
from menu import Menu, MenuItem

intel_children = (
    MenuItem("Packages",
            reverse("intel:packages"),
            weight=10),
    MenuItem("Threat Actors",
            reverse("intel:threatactors"),
            weight=80),
)

Menu.add_item("intel", MenuItem("Intelligence",
    reverse("intel:home"),
    weight=10,
    icon="fa-magic",
    children=intel_children)
)
