
# Changes to ATT&CK in STIX 2.0
## 21 October 2021 - ATT&CK Spec v2.1.0
Changes to ATT&CK in STIX for October 2021 ATT&CK Content Release (ATT&CK-v10.0)

Added full objects for data sources and data components. See [the data sources section of the USAGE document](https://github.com/mitre/cti/blob/master/USAGE.md#data-sources-and-data-components) for more information about data sources, data components, and their relationships with techniques.

Additional data-model improvements with ATT&CK Spec v2.1.0 can be found on [attack-stix-data](https://github.com/mitre-attack/attack-stix-data). See [the changelog](https://github.com/mitre-attack/attack-stix-data/blob/master/CHANGELOG.md) on that repository for more information.

## 21 June 2021 - ATT&CK Spec v2.0.0
Release of ATT&CK in STIX 2.1.

The contents of this repository is not affected, but you can find ATT&CK in STIX 2.1 (ATT&CK spec v2.0.0+) on our new [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) GitHub repository. Both MITRE/CTI (this repository) and attack-stix-data will be maintained and updated with new ATT&CK releases for the foreseeable future, but the data model of attack-stix-data includes quality-of-life improvements not found on MITRE/CTI. Please see the [attack-stix-data USAGE document](https://github.com/mitre-attack/attack-stix-data) for more information on the improved data model of that repository.

## 29 April 2021
Changes to ATT&CK in STIX for April 2021 ATT&CK Content Release (ATT&CK-v9.0)

1. Replaced `GCP`, `AWS` and `Azure` platforms under the enterprise domain with `IaaS` (Infrastructure as a Service).
2. Added `Containers` and `Google Workspace` to the platforms of the enterprise domain.
3. Revised the data sources of the enterprise domain. Data sources are still represented as a string array, but the elements within that array are now formatted `"data source: data component"` to reflect the new data source representation. More information on the new data sources can be found on our [attack-datasources](https://github.com/mitre-attack/attack-datasources) GitHub repository. Note that the data sources in the ICS domain was not affected by this change.

With the release of ATT&CK version 9 we are also hosting an excel representation of the knowledge base on our website. You can find that representation and more about ATT&CK tools on the updated [Working with ATT&CK](https://attack.mitre.org/resources/working-with-attack/) page.

## 27 October 2020
Changes to ATT&CK in STIX for October 2020 ATT&CK Content Release (ATT&CK-v8.0)

1. Added new platforms under the enterprise domain: `Network` and `PRE`.
2. Deprecated the pre-ATT&CK domain. Pre-ATT&CK has been migrated to two new tactics in the Enterprise domain tagged with the `PRE` platform. Please see the new [PRE matrix](https://attack.mitre.org/matrices/enterprise/PRE/) for the replacing Enterprise tactics and techniques. All objects within the pre-ATT&CK domain have been marked as deprecated, along with a new description pointing to their new home in Enterprise.
3. Added the [ATT&CK for ICS domain](ics-attack).

## 8 July 2020 - ATT&CK Spec v1.3.0
Changes to ATT&CK in STIX for July 2020 ATT&CK Content Release (ATT&CK-v7.0)

1. Added sub-techniques:
    - A sub-technique is an attack-pattern where `x_mitre_is_subtechnique` is `true`. 
    - Relationships of type `subtechnique-of` between sub-techniques and techniques convey their hierarchy.

   For more information about the representation of sub-techniques in STIX, please see [the sub-techniques section of the USAGE document](USAGE.md#sub-techniques). 
2. Revised the representation of deprecated objects. The first paragraph of deprecated objects' descriptions should in most cases convey the reason the object was deprecated.

We've also rewritten the [USAGE](USAGE.md) document with additional information about the ATT&CK data model and more examples of how to access and use ATT&CK in Python.

## 24 October 2019
Changes to ATT&CK in STIX for October 2019 ATT&CK Content Release (ATT&CK-v6.0)
1. Added cloud platforms under the enterprise domain: `AWS`, `GCP`, `Azure`, `Office 365`, `Azure AD`, and `SaaS`.

## 31 July 2019
Changes to ATT&CK in STIX for July 2019 ATT&CK Content Release (ATT&CK-v5.0)
1. Descriptions added to relationships of type `mitigates` under the enterprise domain 

## 30 April 2019 - ATT&CK Spec v1.2.0
Changes to ATT&CK in STIX for April 2019 ATT&CK Content Release (ATT&CK-v4.0)
1. `x_mitre_impact_type` added for enterprise techniques within the `Impact` tactic
2. Descriptions added to relationships between software/groups

## 23 October 2018 - ATT&CK Spec v1.1.0
Changes to ATT&CK in STIX for October 2018 ATT&CK Content Release (ATT&CK-v3.0)

1. `x_mitre_platforms` added for enterprise malware/tools
2. `x_mitre_detection` added to attack-patterns
3. Custom MITRE attributes removed from descriptions in attack-patterns
4. Alias descriptions added for malware/tools/intrusion-sets as external references
5. Descriptions added to relationships between groups/attack-patterns in PRE-ATT&CK
6. Names of ATT&CK objects replaced in descriptions and x_mitre_detection fields with markdown links
7. `CAPEC ids` added to external references for attack-patterns
8. Citations in alias descriptions added as external references in the object containing the alias description
9. Added `x-mitre-tactic` and `x-mitre-matrix` objects
10. Changed ===Windows=== subheadings to ### Windows subheadings (Windows is just one example)
11. Added space between asterisks (ex. *Content to * Content) to populate markdown correctly
12. Changed "true" to True in `x_mitre_deprecated`
13. Added old ATT&CK IDs to Mobile/PRE-ATT&CK objects whose IDs have changed as `x-mitre-old-attack-id`