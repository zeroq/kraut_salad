# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem

intel_children = (
    MenuItem("Packages",
            reverse("intel:packages"),
            image="images/Package.svg",
            weight=10),
    MenuItem("Threat Actors",
            reverse("intel:threatactors"),
            image="images/Threat Actor.svg",
            weight=20),
    MenuItem("Campaigns",
            reverse("intel:campaigns"),
            image="images/Campaign.svg",
            weight=30),
    MenuItem("TTPs",
            reverse("intel:ttps"),
            image="images/TTP.svg",
            weight=40),
    MenuItem("Indicators",
            reverse("intel:indicators"),
            image="images/Indicator.svg",
            weight=50),
    MenuItem("Observables",
            reverse("intel:observables"),
            image="images/Observable.svg",
            weight=60),
    MenuItem("Malware Instances",
            reverse("intel:malware_instances"),
            image="images/Kraut.svg",
            weight=70),
    MenuItem("Attack Patterns",
            reverse("intel:attack_patterns"),
            image="images/Kraut.svg",
            weight=80),
)

Menu.add_item("intel", MenuItem("Intelligence",
    reverse("intel:home"),
    weight=10,
    children=intel_children)
)
