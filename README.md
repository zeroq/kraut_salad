# Kraut Salad
Proof of concept implementation of a cyber threat intelligence and incident handling platform

## Current Status
Currently, the basic database design is complete and a first parser for MITRE' stix and cybox cyber threat intelligence exchange formats is written. Kraut Salad is supposed to be a proof of concept implementation to determine if a relational database model is feasible or not. Therefore, Kraut Salad only implements a subset of the MITRE standard and still requires some cybox objects to be implemented.

We also test the django REST framework to see if the capabilities suffice our needs. So far there is no graphical interface or website implemented, thus only the import of stix XML works at the moment.

## Requirements
Please refer to requirements.txt for an updated list of required packages.

## Roadmap
The following items describe what is still planned but has no particular order:

* add more cybox objects (e.g. ProcessObject, HTTPSessionObject, ...)
* add support for IOC format
* create a webinterface to browse and modify threat intelligence data
* create an interface to neo4js graph database
* create a webinterface to track and handle incidents
* associate threat intelligence data with assets detected during an incident
