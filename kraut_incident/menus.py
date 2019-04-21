# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem

incident_children = (
    MenuItem("List Incidents",
            reverse("incidents:list"),
            weight=10,
            image="images/Incident.svg"),
    MenuItem("New Incident",
            reverse("incidents:new"),
            weight=80,
            image="images/NewIncident.svg"),
)

Menu.add_item("incident", MenuItem("Incidents",
    reverse("incidents:home"),
    weight=10,
    children=incident_children)
)
