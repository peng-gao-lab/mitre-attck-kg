#! python3
import os

# Get current workspace path
ROOT = os.path.abspath(".")
FILE_NAME = "enterprise-attack-10.0"

# main entity and properity entity, which will be entity in database
MAIN_ENTITY = []
PPT_ENTITY = []
LEVEL2_PPT = []
ENTITY_WITH_PPT = {}
LEVEL2_PPT_WITH_PPT = {}

# Relationships, except internal  relationships (e.g., owns, listed)
RELAT_TYPE = []

# Save data to json file
MAIN_ENTITY_F = "main_entities"
PPT_ENTITY_F = "property_entities"
ENTITY_WITH_PPT_F = "entities_with_properties"
LEVEL2_PPT_WITH_PPT_F = "level2_properties"
RELAT_TYPE_F = "relationship_types"

# The mapping between Mitre ATTACK terms and STIX2.1 terms
attackToStixTerm = {
    "technique": ["attack-pattern"],
    "tactic": ["x-mitre-tactic"],
    "software": ["tool", "malware"],
    "group": ["intrusion-set"],
    "mitigation": ["course-of-action"],
    "matrix": ["x-mitre-matrix"],
    "data_source": ["x-mitre-data-source"],
    "data_component": ["x-mitre-data-component"]
}
stixToAttackTerm = {
    "attack-pattern": "technique",
    "x-mitre-tactic": "tactic",
    "tool": "software",
    "malware": "software",
    "intrusion-set": "groups",
    "course-of-action": "mitigation",
    "x-mitre-matrix": "matrix",
    "x-mitre-data-source": "data_source",
    "x-mitre-data-component": "data_component"
}

# 
RELATION_ACTORS_MAPPING = {
        "use": ["user", "used"],
        "mitigate": ["mitigator", "mitigated"],
        "subtechnique-of": ["subtech", "supertech"],
        "revoked-by": ["revoked", "revoker"],
        "detect": ["detector", "detected"]
        }

RELATION_TYPE_TRANSFORM = {
        "uses": "use",
        "mitigates": "mitigate",
        "subtechnique-of": "subtechnique-of",
        "revoked-by": "revoked-by",
        "detects": "detect"
        }

