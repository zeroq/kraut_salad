# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem

Menu.add_item("main", MenuItem("Home",
    reverse("home"),
    weight=10))
