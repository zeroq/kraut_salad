# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem

sharing_children = (
    MenuItem("Change Password",
            reverse("accounts:changepw"),
            weight=1,
            image="images/Kraut.svg"
        ),
    MenuItem("Logout",
            reverse("accounts:logout"),
            weight=10,
            image="images/Kraut.svg"
        ),
    #MenuItem("Discover Taxii Feeds",
    #        reverse("sharing:home"),
    #        weight=20,
    #        image="images/Taxii.svg"
    #    ),
    #MenuItem("Poll Taxii Feed",
    #        reverse("sharing:poll"),
    #        weight=30,
    #        image="images/Taxii.svg"
    #    ),
)

Menu.add_item("accounts", MenuItem("Preferences",
    reverse("accounts:login"),
    weight=10,
    children=sharing_children)
)
