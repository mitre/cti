# Introduction
This document describes how to query and manipulate CAPEC data in this repository. Machine-readable CAPEC data is available in
a JSON-based [STIX 2.0 and STIX 2.1 formats](https://oasis-open.github.io/cti-documentation/stix/intro). See [Release Notes](#release-notes) for any changes to the generation of the STIX CAPEC data.

STIX 2.x is just JSON and so should be very accessible from Python and other programming languages. If you are using Python, the [python-stix2](https://github.com/oasis-open/cti-python-stix2) library can help you work with the content as shown in the examples below.

# Mapping Concepts
First, we must describe how CAPEC objects and properties map to STIX 2.x objects and properties.

## Objects
In CAPEC, the main object is the Attack Pattern. Most Attack Pattern also have Mitigations. There are other types of objects in CAPEC (e.g, Category, View, etc.), but these are not (currently) part of the repository.  

The STIX types are found as literal strings assigned to the `type` property of the STIX JSON object. The STIX 2.x object called "Attack Pattern" corresponds to a CAPEC attack pattern. In STIX 2.x, there are objects called "Course(s) of Action" which can be used to describe CAPEC Mitigations.  

## Properties
The following is a table mapping of CAPEC properties to STIX properties. Some of these properties are standard STIX properties, while others were custom-created for compatibility with CAPEC. These properties are accessed from STIX objects as JSON properties.

### Attack Pattern Properties
| CAPEC 3.6 Property | STIX Properties | STIX type |
| --------------- |  --------------- | --------------- |
**Name** |  `name` | string |
**Description** |  `description` | string
**Extended_Definition** | `x_capec_extended_definition` | string
**Abstraction** | `x_capec_abstraction` | enumeration(`Meta, Standard, Detailed`)
**Alternate\_Terms** |  `x_capec_alternate_terms` | list(string)
**Consequences** |  `x_capec_consequences` | dictionary(enumeration(`High, Medium, Low`), string)
**Example\_Instances** | `x_capec_example_instances` | list(string)
**Execution\_Flows** | `x_capec_execution_flows` | (XHTML) string
**Likelihood\_Of\_Attack** | `x_capec_likelihood_of_attack` | enumeration(`High, Medium, Low`)
**Notes** | **Other\_Notes** | `x_capec_notes` | list(string)
**Prerequisites** | `x_capec_prerequisites` | list(string)
**Skills\_Required** | `x_capec_skills_required` | dictionary(string, enumeration(`High, Medium, Low`))
**Typical\_Severity** |  `x_capec_typical_severity` | enumeration(`High, Medium, Low`)
**ID** |  `external_references[i].external_id where external_references[i].source_name == "capec"` | integer 
**Related\_Weaknesses** |  `external_references[i].external_id where external_references[i].source_name == "cwe"` | integer 
**References** | `external_references[i].external_id where external_references[i].source_name == "reference_from_CAPEC"` | `external-reference`
**Mitigation** | `relationship_type == "mitigates"` | `relationship`

### Attack Pattern Relationships
| CAPEC 3.6 Relationship | STIX Properties | STIX type |
| --------------- |  --------------- | --------------- |
**parent_of** | `x_capec_parent_of_refs` | list(identifier)
**child_of** | `x_capec_child_of_refs` | list(identifier)
**can_precede** | `x_capec_can_precede_refs` | list(identifier)
**can_follow** | `x_capec_can_follow_refs` | list(identifier)
**peer_of** | `x_capec_peer_of_refs` | list(identifier)

CAPEC 3.6 properties not mapped (at this time):  **Indicators**, **Taxonomy\_Mappings**, **Content\_History**

CAPEC 3.6 properties not appropriate to map: **Status**

# Using Python and STIX 2.x
In this section, we will describe how to query and manipulate CAPEC data that has been stored in a STIX 2.x repository. A Python library has been created for using and creating STIX 2.x data by the OASIS Technical Committee for Cyber Threat Intelligence, which develops the STIX standard. This library abstracts storage and transport details so that the same code can be used to interact with data locally on the filesystem or in memory, or remotely via [TAXII](https://oasis-open.github.io/cti-documentation/taxii/intro). The source code, installation instructions, and basic documentation for the library can be found [here](https://github.com/oasis-open/cti-python-stix2). There is a more thorough [API documentation](http://stix2.readthedocs.io/en/latest/overview.html) as well.

## Python Library
To begin querying STIX 2.x data, you must first have a [DataSource](http://stix2.readthedocs.io/en/latest/guide/datastore.html). For these examples, we will simply use a [FileSystemSource](http://stix2.readthedocs.io/en/latest/guide/filesystem.html). The CAPEC corpus must first be cloned or downloaded from [GitHub](https://github.com/mitre/cti).

### Get all Attack Patterns
Once the stix2 Python library is installed and the corpus is acquired, we need to open the DataStore for querying:

```python
from stix2 import FileSystemSource
fs = FileSystemSource('./cti/capec')
```

When creating the DataSource, the keyword agrument `allow_custom` must be set to `True`. This is because the CAPEC data uses several custom properties which are not part of the STIX 2.x specification (`x_capec_prerequisites`, `x_capec_example_instances`, etc).

To perform a query, we must define a [Filter](http://stix2.readthedocs.io/en/latest/guide/datastore.html#Filters). As of this writing, a filter must, at a minimum, specify object `id`'s or an object `type`.  The following filter can be used to retrieve all CAPEC attack patterns:

```python
from stix2 import Filter
filt = Filter('type', '=', 'attack-pattern')
```

Once this filter is defined, you can pass it to the DataSource `query` function in order to actually query the data:

```python
attack_patterns = fs.query([filt])
```

Notice that the `query` function takes a **list** of filters.  These filters are logically AND'd together during the query. As of this writing, `allow_custom` must be set to `True` in order to query CAPEC data. This is because the CAPEC data uses several custom properties which are not part of the STIX 2.0 specification (`x_capec_prerequisites`, `x_capec_example_instances`, etc).

**For the remaining examples, these imports and the FileSystemStore initialization will be omitted.**


### Get any object by CAPEC ID
In this example, the STIX 2.x type must be passed into the function. Here we query for the attack pattern with ID `66` (*SQL Injection*).

```python
def get_attack_pattern_by_capec_id(src, capec_id):
    filt = [
        Filter('type', '=', 'attack-pattern'),
        Filter('external_references.external_id', '=', 'CAPEC-' + capec_id),
        Filter('external_references.source_name', '=', 'capec'),
    ]
    return src.query(filt)

get_attack_pattern_by_capec_id(fs, '66')
```

### Get all Mitigations for specific Attack Pattern
The mitigations for a technique are stored in objects separate from the technique. These objects are found through a `mitigates` relationship.

```python
def get_mitigations_by_attack_pattern(src, ap_stix_id):
    relations = src.relationships(ap_stix_id, 'mitigates', target_only=True)
    return src.query([
        Filter('type', '=', 'course-of-action'),
        Filter('id', 'in', [r.source_ref for r in relations])])

ap = get_attack_pattern_by_capec_id(fs, '66')[0]
get_mitigations_by_attack_pattern(fs, ap.id)
```

### Release Notes

The STIX CAPEC data is generated by a python script named `capec2stix`.  In this section the changes to the script for each new CAPEC release is listed.

## Release for CAPEC 3.6

* Added the `x_capec_extended_definition` property

## Release for CAPEC 3.5 

* Added functionality to infer CAPEC ParentOf and CanFollow relationships:
  - CAPEC does not explicitly state these relationships, so they needed to be inferred by looking at the children's "ChildOf" relationship and the can follows' "CanPrecede" relationship and work backwards
  - A global map of CAPEC ids to STIX ids was created by iterating through all CAPEC objects and creating STIX ids
  - Global maps of CAPEC ids to list of children CAPEC ids and list of CAPEC ids that can follow was created by iterating through all CAPEC objects
  - When creating STIX Attack Pattern objects, the child and can follow maps are used to find the relationships that are not explicitly stated in the CAPEC object and the STIX id map is used to get the STIX ID for the related CAPECs
* Added the following properties to the Attack Pattern STIX object:
  - `x_capec_child_of_refs`: contains a list of STIX ids of the Attack Pattern objects which the current object is a child of
  - `x_capec_parent_of_refs`: contains a list of STIX ids of the Attack Pattern objects which the current object is a parent of
  - `x_capec_can_precede_refs`: contains a list of STIX ids of the Attack Pattern objects which the current object can precede
  - `x_capec_can_follow_refs`: contains a list of STIX ids of the Attack Pattern objects which the current object can follow
  - `x_capec_peer_of_refs`: contains a list of STIX ids of the Attack Pattern objects which the current object is a peer of
* Added "allow_custom=True" as a flag when creating STIX bundles to satisfy the requirements for the new STIX release
