# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.core.urlresolvers import reverse
from menu import Menu, MenuItem

Menu.add_item("main", MenuItem("Home",
                               reverse("kraut_base.views.home"),
                               weight=10,
                               icon='fa-home'))
