# Introduction
This document describes how to query and manipulate ATT&CK data in this repository. Machine-readable ATT&CK data is currently available via two mechanisms:
* a JSON-based [STIX 2.0](https://oasis-open.github.io/cti-documentation/stix/intro) format.
* a [TAXII Server](https://medium.com/mitre-attack/att-ck-content-available-in-stix-2-0-via-public-taxii-2-0-server-317e5c41e214) hosting the same STIX 2.0 content

The MediaWiki API was deprecated with the ATT&CK content release in October 2018 and fully removed on February 12th, 2019. Luckily, STIX 2.0 is just JSON and so should be very accessible from Python and other programming languages. If you are using Python, the [python-stix2](https://github.com/oasis-open/cti-python-stix2) library can help you work with the content as shown in the examples below. 

# Mapping Concepts
First, we must describe how ATT&CK objects and properties map to STIX 2.0 objects and properties.

## Objects
In ATT&CK, there are three main concepts (excluding Tactics for now): Techniques, Groups, and Software. Most techniques also have Mitigations. STIX 2.0 describes these as objects and uses different terminology to describe them. The following table is a mapping of ATT&CK concepts to STIX 2.0 objects:

ATT&CK concept | STIX Object type
---------------|-----------------
Technique | `attack-pattern`
Group | `intrusion-set`
Software | `malware` or `tool`
Mitigation | `course-of-action`
Tactic | `x-mitre-tactic`
Matrix | `x-mitre-matrix`

The above STIX types are found as literal strings assigned to the `type` property of the STIX JSON object. As shown in the table, in STIX 2.0, there are objects called "Course(s) of Action" used to describe mitigations to ATT&CK techniques. Similarly, the STIX 2.0 object called "Attack Pattern" describes techniques, etc. It should also be noted that Tactics are not an explicit object type in STIX 2.0, and they are referenced implicitly as kill chain phases within the other object types, as described in the tables below.

## Properties
The following is a table mapping of ATT&CK properties, the old ATT&CK MediaWiki names, and the new STIX properties. Some of these properties are standard STIX properties, while others were custom-created for compatibility with ATT&CK. These properties are accessed from STIX objects as JSON properties.

### Migrating from MediaWiki

### Common properties (on all objects)
ATT&CK Property | ATT&CK MediaWiki | STIX Properties
--------------- | ---------------- | ---------------
**Entry ID**    | `Has ID` | `external_references[i].external_id` where `external_references[i].source_name == "mitre-attack"`
**Entry URL**   | `URL` | `external_references[i].url` where `external_references[i].source_name == "mitre-attack"`
**Entry Title** | `Has display name` | `name`
**Entry Text**  | `Has description` | `description`
**Citation**    | `Citation reference` | `external_references`
**Deprecated**  | `Deprecated` | `x_mitre_deprecated`
**Revoked**     | `Not available via MediaWiki API` | `revoked`
**Old ATT&CK ID** | `Not available via MediaWiki API` | `x_mitre_old_attack_id`


### Techniques
ATT&CK Property | ATT&CK MediaWiki | STIX Properties
--------------- | ---------------- | ---------------
**Entry Title** | `Has technique name` | `name`
**Tactic** | `Has tactic` | `kill_chain_phases[i].phase_name` where `kill_chain_phases[i].kill_chain_name == "mitre-attack"`
**Description** | `Has technical description` | `description`
**Mitigation** | `Has mitigation` | `relationship` where `relationship_type == "mitigates"`, points from a source object with `type=="course-of-action"`, which contains a `description`
**Detection** | `Has detection` | `description` (inline heading of Detection)
**Examples** | in software, groups as `Has technique` | `relationship`, points from the `attack-pattern` to and from `malware`, `tool`, and `intrusion-set`
**Platform** | `Has platform` | `x_mitre_platforms`
**Data Sources** | `Has data source` | `x_mitre_data_sources`
**Permissions Required** | `Requires permissions` | `x_mitre_permissions_required`
**Effective Permissions** | `Has effective permissions` | `x_mitre_effective_permissions`
**Defense Bypassed** | `Bypasses defense` | `x_mitre_defense_bypassed`
**System Requirements** | `Has system requirements` | `x_mitre_system_requirements`
**Network Requirements** | `Has network requirements` | `x_mitre_network_requirements`
**Remote Support** | `Has remote support` | `x_mitre_remote_support`
**Contributors** | `Has contributor` | `x_mitre_contributors`
**Impact Type** | `Not available via MediaWiki API` | `x_mitre_impact_type`


### Software
ATT&CK Property | ATT&CK MediaWiki | STIX Properties
--------------- | ---------------- | ---------------
**Techniques Used** | `Has technique` | `relationship` where `relationship_type == "uses"`, points to a `target` object with `type== "attack-pattern"`
**Aliases** | `Has alias` | `x_mitre_aliases`
**Groups** | `Has groups` | `relationship` where `relationship_type == "uses"`, points from a `source` object with `type== "intrusion-set"`
**Contributors** | `Has contributor` | `x_mitre_contributors`

### Groups
ATT&CK Property | ATT&CK MediaWiki | STIX Properties
--------------- | ---------------- | ---------------
**Techniques Used** | `Has technique` | relationship where `relationship_type == "uses"`, points to a `target` object with `type == "attack-pattern"`
**Alias Descriptions** | `Has alias` | `aliases`
**Software** | `Has groups` | `relationship` where `relationship_type == "uses"`, points to a `target` object with `type== "malware" or "tool"`
**Contributors** | `Has contributor` | `x_mitre_contributors`

# Using Python and STIX 2.0
In this section, we will describe how to query and manipulate ATT&CK data that has been stored in a STIX 2.0 repository. A Python library has been created for using and creating STIX 2.0 data by the OASIS Technical Committee for Cyber Threat Intelligence, which develops the STIX standard. This library abstracts storage and transport details so that the same code can be used to interact with data locally on the filesystem or in memory, or remotely via [TAXII](https://oasis-open.github.io/cti-documentation/taxii/intro). The source code, installation instructions, and basic documentation for the library can be found [here](https://github.com/oasis-open/cti-python-stix2). There is a more thorough [API documentation](http://stix2.readthedocs.io/en/latest/overview.html) as well.

## Python Library
To begin querying STIX 2.0 data, you must first have a [DataSource](http://stix2.readthedocs.io/en/latest/guide/datastore.html). For these examples, we will simply use a [FileSystemSource](http://stix2.readthedocs.io/en/latest/guide/filesystem.html). The ATT&CK corpus must first be cloned or downloaded from [GitHub](https://github.com/mitre/cti).

**Note** for this example we used the enterprise-attack corpus to demonstrate usage. The same can be done for all other data sources.

### Get all Techniques
Once the stix2 Python library is installed and the corpus is acquired, we need to open the DataStore for querying:

```python
from stix2 import FileSystemSource
fs = FileSystemSource('./cti/enterprise-attack')
```

To perform a query, we must define a [Filter](http://stix2.readthedocs.io/en/latest/guide/datastore.html#Filters). As of this writing, a filter must, at a minimum, specify object `id`'s or an object `type`.  The following filter can be used to retrieve all ATT&CK techniques:

```python
from stix2 import Filter
filt = Filter('type', '=', 'attack-pattern')
```

Once this filter is defined, you can pass it to the DataSource `query` function in order to actually query the data:

```python
techniques = fs.query([filt])
```

Notice that the `query` function takes a **list** of filters.  These filters are logically AND'd together during the query. As of this writing, `allow_custom` must be set to `True` in order to query ATT&CK data. This is because the ATT&CK data uses several custom properties which are not part of the STIX 2.0 specification (`x_mitre_platforms`, `x_mitre_contributors`, etc). **UPDATE(8-March-2018)**: Python STIX-2 has moved 'allow_custom' to be set at the DataStore/Source level, not within each API call (i.e. get(), query() etc...). Also, all DataStores/Sources by default now set 'allow_custom' to True.

**For the remaining examples, these imports and the FileSystemStore initialization will be omitted.**

### Get all Software
Since ATT&CK software can either be classified as a `tool` or `malware` in STIX, you must query for both of them in order to find all software. The library's `query` function does not have the capability to do logical OR, so two separate queries must be performed.  The results are merged together into one list.

```python
from itertools import chain

def get_all_software(src):
    filts = [
        [Filter('type', '=', 'malware')],
        [Filter('type', '=', 'tool')]
    ]
    return list(chain.from_iterable(
        src.query(f) for f in filts
    ))
    
get_all_software(fs)
```

### Get Techniques by name or content
Here we query the same technique in two different ways. In addition to the `Rundll32` technique, notice that the latter method results in a second technique (`Masquerading`) because it also contains the term "rundll32.exe" in its description.

```python
def get_all_techniques(src):
    filt = [Filter('type', '=', 'attack-pattern')]
    return src.query(filt)
    
def get_technique_by_name(src, name):
    filt = [
        Filter('type', '=', 'attack-pattern'),
        Filter('name', '=', name)
    ]
    return src.query(filt)

def get_techniques_by_content(src, content):
    techniques = get_all_techniques(src)
    return [
        tech for tech in techniques
        if content.lower() in tech.description.lower()
    ]
    
get_technique_by_name(fs, 'Rundll32')
get_techniques_by_content(fs, 'rundll32.exe')
```

### Get Techniques added since a certain time
This example shows how you can use the `Filter` API to only get techniques that have been added to the STIX content since a certain time based on the `created` timestamp. This code could be used within a larger function or script to alert when a new technique has been added to the ATT&CK STIX/TAXII content. The type could also be changed (or removed completely) to return results for different objects.

```python
def get_techniques_since_time(src, timestamp):
    filt = [
        Filter('type', '=', 'attack-pattern'),
        Filter('created', '>', timestamp)
    ]
    return src.query(filt)
    
get_techniques_since_time(src, "2018-10-01T00:14:20.652Z")
```

### Get any object by ATT&CK ID
In this example, the STIX 2.0 type must be passed into the function. Here we query for the group with ATT&CK ID `G0016` (*APT29*).

```python
def get_object_by_attack_id(src, typ, attack_id):
    filt = [
        Filter('type', '=', typ),
        Filter('external_references.external_id', '=', attack_id)
    ]
    return src.query(filt)

get_object_by_attack_id(fs, 'intrusion-set', 'G0016')
```

### Get Group by alias
Here we query the group *APT29* by one of its aliases.

```python
def get_group_by_alias(src, alias):
    return src.query([
        Filter('type', '=', 'intrusion-set'),
        Filter('aliases', '=', alias)
    ])
    
get_group_by_alias(fs, 'Cozy Bear')[0]
```

### Get all Techniques used by a Group
We query for the techniques that are directly connected to a group.  This does NOT include techniques which are only used by the group's software.

```python
def get_technique_by_group(src, stix_id):
    relations = src.relationships(stix_id, 'uses', source_only=True)
    return src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', 'in', [r.target_ref for r in relations])
    ])

group = get_group_by_alias(fs, 'Cozy Bear')[0]
get_technique_by_group(fs, group)
```

### Get all Techniques used By a Group's Software
This example is fairly complex.  First we must query the group's relationships to find the software that the group uses.  Then we must use the relationships for each piece of software in order to find the techniques.  Notice the expression for `software_uses` involves directly filtering the relationship objects rather than using the `relationships` method of the DataSource `src`.  This is because, as of this writing, calls to `query` are expensive, and it is better to minimize them.

```python
from stix2.utils import get_type_from_id

def get_techniques_by_group_software(src, group_stix_id):
    # get the malware, tools that the group uses
    group_uses = [
        r for r in src.relationships(group_stix_id, 'uses', source_only=True)
        if get_type_from_id(r.target_ref) in ['malware', 'tool']
    ]

    # get the technique stix ids that the malware, tools use
    software_uses = src.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', 'uses'),
        Filter('source_ref', 'in', [r.source_ref for r in group_uses])
    ])

    #get the techniques themselves
    return src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', 'in', [r.target_ref for r in software_uses])
    ])

group = get_group_by_alias(fs, 'Cozy Bear')[0]
get_techniques_by_group_software(fs, group)
```

### Get all Groups and Software that use a specific Technique
Notice that a relationship that `uses` an `attack-pattern` will always be `target_ref` for an `intrusion-set`, `tool` or `malware`. This example is broken down to separate groups from software, but it could have been made in a single step.

```python
def get_technique_users(src, tech_stix_id):
    groups = [
        r.source_ref
        for r in src.relationships(tech_stix_id, 'uses', target_only=True)
        if get_type_from_id(r.source_ref) == 'intrusion-set'
    ]

    software = [
        r.source_ref
        for r in src.relationships(tech_stix_id, 'uses', target_only=True)
        if get_type_from_id(r.source_ref) in ['tool', 'malware']
    ]

    return src.query([
        Filter('type', 'in', ['intrusion-set', 'malware', 'tool']),
        Filter('id', 'in', groups + software)
    ])
    
tech = get_technique_by_name(fs, 'Rundll32')[0]
get_technique_users(fs, tech.id)
```

### Get all Techniques for specific platform
Notice how the query is filtered by `x_mitre_platforms` using the `=` operator and a single `platform`, even though `x_mitre_platforms` is a list type. This means that for list properties, the `=` operator simply checks to see if the item is in the list.

```python
def get_techniques_by_platform(src, platform):
    return src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('x_mitre_platforms', '=', platform)
    ])
    
get_techniques_by_platform(fs, 'Windows 8')
```

### Get all Techniques for specific Tactic
You can also filter on sub-properties.  In this example, we filter on the `phase_name` property within the `kill_chain_phases` property.

```python
def get_tactic_techniques(src, tactic):
    techs =  src.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('kill_chain_phases.phase_name', '=', tactic)
    ])

    # double checking the kill chain is MITRE ATT&CK
    return [t for t in techs if {
            'kill_chain_name' : 'mitre-attack',
            'phase_name' : tactic,
    } in t.kill_chain_phases]

get_tactic_techniques(fs, 'defense-evasion')
```

### Get all Mitigations for specific Technique
The mitigations for a technique are stored in objects separate from the technique. These objects are found through a `mitigates` relationship.

```python
def get_mitigations_by_technique(src, tech_stix_id):
    relations = src.relationships(tech_stix_id, 'mitigates', target_only=True)
    return src.query([
        Filter('type', '=', 'course-of-action'),
        Filter('id', 'in', [r.source_ref for r in relations])
    ])

tech = get_technique_by_name(fs, 'Rundll32')[0]
get_mitigations_by_technique(fs, tech.id)
```

### Get all Tactics for Matrix
The tactics are individual objects (`x-mitre-tactic`), and their order in a matrix (`x-mitre-matrix`) is found within the `tactic_refs` property in a matrix. The order of the tactics in that list matches the ordering of the tactics in that matrix. You can get all matrices and tactics in Enterprise ATT&CK (or in any other ATT&CK domain) by using the following code.

```python
def getTacticsByMatrix(src):
    tactics = {}
    matrix = src.query([
        Filter('type', '=', 'x-mitre-matrix'),
    ])

    for i in range(len(matrix)):
        tactics[matrix[i]['name']] = []
        for tactic_id in matrix[i]['tactic_refs']:
            tactics[matrix[i]['name']].append(src.query([Filter('id', '=', tactic_id)])[0])    
    
    return tactics
```

### Get an Object that revoked a previous Object
If an object is revoked by another object, whether it's a group/software/technique/x-mitre-tactic/x-mitre-matrix, that means that the object was replaced by a new object. You can find what object replaced the original object by supplying the *stix_id* of the revoked object to the following function.

```python
def getRevokedBy(stix_id, src):
    relations = src.relationships(stix_id, 'revoked-by', source_only=True)
    revoked_by = src.query([
        Filter('id', 'in', [r.target_ref for r in relations]),
        Filter('revoked', '=', False)
    ])
    if revoked_by is not None:
        revoked_by = revoked_by[0]

    return revoked_by
 ```
## FAQ

### Is it possible to query multiple ATT&CK sources at the same time?

Yes! Using a [CompositeDataSource](https://stix2.readthedocs.io/en/latest/guide/datastore.html#CompositeDataSource) you can collectively query multiple sources with the same filter. An example below using the FileSystemSource.

```python
import stix2

enterprise_attack_fs = stix2.FileSystemSource("./cti/enterprise-attack")
pre_attack_fs = stix2.FileSystemSource("./cti/pre-attack")
mobile_attack_fs = stix2.FileSystemSource("./cti/mobile-attack")

composite_ds = stix2.CompositeDataSource()
composite_ds.add_data_sources([enterprise_attack_fs, pre_attack_fs, mobile_attack_fs])

q1 = stix2.Filter("name", "=", ".bash_profile and .bashrc")
q2 = stix2.Filter("type", "=", "attack-pattern")

print(composite_ds.query(q1))
print(composite_ds.query(q2))
```
