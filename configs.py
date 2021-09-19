#! python3
import os

# Get current workspace path
ROOT = os.path.abspath(".")
FILE_NAME = "enterprise-attack"

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

attackToStixTerm = {
    "technique": ["attack-pattern"],
    "tactic": ["x-mitre-tactic"],
    "software": ["tool", "malware"],
    "group": ["intrusion-set"],
    "mitigation": ["course-of-action"],
    "matrix": ["x-mitre-matrix"],
}
stixToAttackTerm = {
    "attack-pattern": "technique",
    "x-mitre-tactic": "tactic",
    "tool": "software",
    "malware": "software",
    "intrusion-set": "group",
    "course-of-action": "mitigation",
    "x-mitre-matrix": "matrix"
}
