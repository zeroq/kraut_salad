# Kraut Salad
Proof of concept implementation of a cyber threat intelligence and incident handling platform

## Current Status
Currently, the basic database design is complete and a first parser for MITRE' stix and cybox cyber threat intelligence exchange formats is written. Kraut Salad is supposed to be a proof of concept implementation to determine if a relational database model is feasible or not. Therefore, Kraut Salad only implements a subset of the MITRE standard and still requires some cybox objects to be implemented.

We also test the django REST framework to see if the capabilities suffice our needs. So far there is no graphical interface or website implemented, thus only the import of stix XML works at the moment.
