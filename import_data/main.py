#! python3
import os, sys, json, logging

sys.path.append("..")
from configs import *
from stix2 import Filter, MemoryStore
from templates import *

# remove revoked and depreceted objects
# refer to https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md#working-with-deprecated-and-revoked-objects
def remove_revoked_deprecated(stix_objects):
    """Remove any revoked or deprecated objects from queries made to the data source"""
    # Note we use .get() because the property may not be present in the JSON data. The default is False
    # if the property is not set.
    return list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
            stix_objects
        )
    )

def main():
    # 1. Insert identity
    # 2. Insert marking-definition -> add relations with identity
    # 3. Insert technique -> add relations with identity and marking-dinifinition
    # 4. software -> add relations with all above
    # 5. groups -> ...
    # 6. ...
    # If one entity has kill_chain_phases or external_references propertities, then add corresponding entities
    return True

if __name__ == "__main__":
    main()
