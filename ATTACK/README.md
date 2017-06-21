# ATT&CK - STIX Content 
The STIX content found here is the unabridged conversion of the MITRE ATT&CK catalog in its entirety. All of the converted STIX Objects can be found individually in all the subdirectories enumerated here (i.e. organized by STIX object type) OR compiled in a single json file (mitre-attack.json). The STIX 2.0 content is in the json format.

## ATT&CK -> STIX 2.0 Mapping (High-Level)
* ATT&CK Technique -> STIX Attack-Pattern
* ATT&CK Tactic -> STIX Attack-Pattern.Kill-Chain-Phase
* ATT&CK Group -> STIX Intrusion-Set
* ATT&CK Software -> STIX Malware (OR) STIX Tool
* ATT&CK Mitigation -> STIX Course-of-Action

## Life Cycle
As the MITRE ATT&CK catalog - to include Tactics, Techniques, Groups, Software, and Mitigations - is further developed and expanded, so to will this repository of translated STIX content. Any modification to the ATT&CK catalog triggers an immediate process to assess and update the existing STIX content found here. 

Explicit concern is paid to the maintenance of the STIX Object versions. All converted ATT&CK content follows the STIX versioning policy (read the docs: https://oasis-open.github.io/cti-documentation/). 
