### Changes to STIX for October 2019 ATT&CK Content Release (ATT&CK-v6.0)
1. Added cloud platforms under the enterprise domain: `AWS`, `GCP`, `Azure`, `Office 365`, `Azure AD`, and `SaaS`.

### Changes to STIX for July 2019 ATT&CK Content Release (ATT&CK-v5.0)
1. Descriptions added to relationships of type `mitigates` under the enterprise domain 

### Changes to STIX for April 2019 ATT&CK Content Release (ATT&CK-v4.0)
1. `x_mitre_impact_type` added for enterprise techniques within the `Impact` tactic
2. Descriptions added to relationships between software/groups

### Changes to STIX for October 2018 ATT&CK Content Release (ATT&CK-v3.0)

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
