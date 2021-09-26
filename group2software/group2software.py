#! python3
import os, sys, json, logging
sys.path.append("..")
from configs import *
from stix2 import MemoryStore, Filter

# Setting
DATA_PATH = os.path.join(os.path.pardir, "data")
RES_NAME = "group2software"
logging.basicConfig(level=logging.DEBUG)

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
    src = MemoryStore(allow_custom=True)
    filePath = os.path.join(DATA_PATH, FILE_NAME + '.json')
    try:
        logging.debug("Loading data from {}".format(filePath))
        src.load_from_file(filePath)
    except BaseException:
        logging.error("Load data error.")
        return
    else:
        logging.debug("Data loaded.")

    res = {}
    queryGroups = [Filter("type", "=", "intrusion-set")]
    groups = src.query(queryGroups)
    groups = remove_revoked_deprecated(groups)
    logging.debug("Groups filtering done. Groups number: {}".format(len(groups)))

    # Traverse all groups
    for group in groups:
        softwareList = {}
        groupId = group.get("id")
        groupName = group.get("name")
        if not groupId or not groupName:
            logging.error("{} has no group id or name".format(group))
            continue
        queryRelations = [Filter("type", "=", "relationship"),
                        Filter("source_ref", "=", groupId),
                        Filter("relationship_type", "=", "uses")]
        relations = src.query(queryRelations)

        # Traverse all relations related with this group
        for relation in relations:
            softwareId = relation.get("target_ref")
            if not softwareId:
                logging.error("{} has no target id".format(relation))
                continue

            # Find related softwares
            querySoftware = [Filter("id", "=", softwareId)]
            softwares = src.query(querySoftware)
            if len(softwares) == 0 or len(softwares) > 1:
                logging.error("{} related to {} softwares".format(softwareId, len(softwares)))
                continue
            else:
                software = softwares[0]
            name = software.get("name")
            ttype = software.get("type")
            if not name or not ttype:
                logging.error("{} has no name or type property".format(software))
                continue
            if ttype in ["tool", "malware"]:
                softwareList[name] = ttype

        res[groupName] = softwareList
    logging.debug("Successfully get results")

    resFile = os.path.join(os.path.abspath('.'), RES_NAME + '.json')
    with open(resFile, 'w') as fo:
        json.dump(res, fo, indent=4)
    logging.debug("Successfully dump results")

    return



if __name__ == "__main__":
    main()
