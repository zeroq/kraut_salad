### RESTful API

The API currently supports the following requests:

* `GET /api/packages`: List all intelligence packages
* `GET /api/packages/<ID>`: List details of a specific intelligence package
* `GET /api/packages/<ID>/threatactors`: List all threat actors belonging to an intelligence package
* `GET /api/packages/<ID>/campaigns`: List all campaigns belonging to an intelligence package
* `GET /api/packages/<ID>/indicators`: List all indicators belonging to an intelligence package
* `GET /api/packages/<ID>/observables`: List all observables belonging to an intelligence package
* `GET /api/packages/<ID>/quick`: Get a simple list of important information such as IPs, Domains, Hashes for an intelligence package
* `GET /api/threatactors`: List all threat actors
* `GET /api/threatactors/<ID>`: List details of a specific threat actor
* `GET /api/threatactors/<ID>/associated`: List all associated threat actors of a specific threat actor
* `GET /api/threatactors/<ID>/campaigns`: List all campaigns of a specific threat actor
* `GET /api/campaigns`: List all campaigns
* `GET /api/campaigns/<ID>`: List details of a specific campaign
* `GET /api/campaigns/<ID>/related`: List all related campaigns of a specific campaign
* `GET /api/indicators`: List all indicators
* `GET /api/indicators/<ID>`: List details of a specific indicator
* `GET /api/indicators/<ID>/related/`: List all related indicators
* `GET /api/indicators/<ID>/observables/`: List all embedded observables of an indicator
* `GET /api/observables`: List all observables
* `GET /api/observables/<ID>`: List details of a specific observable
* `GET /api/observables/<ID>/related_objects`: List all related objects of a specific observable
* `GET /api/observables/<ID>/related_packages`: List all related intelligence packages of a specific observable
* `GET /api/observables/<ID>/related_indicators`: List all related indicators of a specific observable
* `GET /api/packagesd3/tree/<ID>/`: Get a list of nodes and links to be used for D3.js graphing of a package
