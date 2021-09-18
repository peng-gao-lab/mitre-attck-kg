#! python3
import os

ROOT = os.getcwd()
FILE_NAME = "enterprise-attack"
TYPE = []
RELATIONSHIP_TYPE = []

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
