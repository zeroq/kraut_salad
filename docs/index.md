# Kraut Salad

A proof of concept implementation of a cyber threat 
intelligence and incident management platform
made in Germany.

The parsing component of Kraut Salad currently supports 
the cyber threat intelligence standards by Mitre called 
[STIX](https://stix.mitre.org) and [CybOX](https://cybox.mitre.org).
For future versions, we plan to extend the parser to 
also read OpenIOC and other open source intelligence feeds.

The basis of Kraut Salad is a PostgreSQL database that 
holds tables for different kinds of threat intelligence
objects, such as threat actors, campaigns, and items that
can be used in indicators or that are observable at the
host or on the network, as Mitre calls them in its CybOX 
standard.

Next to the storage of cyber threat intelligence information,
we plan to integrate an incident management platform which will
enable us to associate intelligence information with assets
that were affected in an incident and actions that were performed
on such information (e.g. network indicators were searched at
the enterprise proxies), in order to get a better
understanding and overview of an incident.

## Quick Start

* Kraut Salad is based on [Python](http://www.python.org) and [Python Django](https://www.djangoproject.com)

* Get the Kraut Salad sources from Github:

        git clone https://github.com/zeroq/kraut_salad.git

* Install the requirements:

        pip install -r requirements.txt

* In order to import a STIX document into Kraut Salad issue:

        python manage.py load_stix <path_to_stix_xml>

## Current Status

At its current development status Kraut Salad does not offer a
fully functional graphical interface yet. We are working on a webinterface to
browse, add, and modify imported data, but it is not in a usable
status at this time. Checkout the screenshots page to see current
experiments with visualization and general look and feel of the
webinterface.

However, we integrated the [Django REST
Framework](http://www.django-rest-framework.org) to have an
API to interact with the imported data.

## Content

* [Home](index.md)

* [RESTful API](api.md)

* [Screenshots](screenshots.md)
