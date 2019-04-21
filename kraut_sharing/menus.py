# vim: tabstop=4 expandtab shiftwidth=4 softtabstop=4

from django.urls import reverse
from menu import Menu, MenuItem

sharing_children = (
    MenuItem("Manage TAXII Servers",
            reverse("sharing:servers"),
            weight=10,
            image="images/Taxii.svg"
        ),
    MenuItem("Manage TAXII Collections",
            reverse("sharing:collections"),
            weight=15,
            image="images/Taxii.svg"
        ),
    ### Deprecated items - will be removed or changed in near future
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

Menu.add_item("sharing", MenuItem("Sharing",
    reverse("sharing:home"),
    weight=10,
    children=sharing_children)
)
