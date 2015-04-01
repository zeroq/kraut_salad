# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.core.urlresolvers import reverse
from menu import Menu, MenuItem

intel_children = (
    MenuItem("Packages",
            reverse("intel:packages"),
            image="images/Package.png",
            weight=10),
    MenuItem("Threat Actors",
            reverse("intel:threatactors"),
            image="images/Threat Actor.png",
            weight=20),
    MenuItem("Campaigns",
            reverse("intel:campaigns"),
            image="images/Campaign.png",
            weight=30),
    MenuItem("Indicators",
            reverse("intel:indicators"),
            image="images/Indicator.png",
            weight=40),
    MenuItem("Observables",
            reverse("intel:observables"),
            image="images/Observable.png",
            weight=50),
)

Menu.add_item("intel", MenuItem("Intelligence",
    reverse("intel:home"),
    weight=10,
    icon="fa-magic",
    children=intel_children)
)
