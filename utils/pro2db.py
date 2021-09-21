#!python3
import os, sys, logging, json

sys.path.append("..")
from configs import *
from stix2 import MemoryStore, Filter

# Setting
DATA_PATH = os.path.join(os.path.pardir, "data")
COMMON_PPT_F = "common_properties"
PARTICULAR_PPT_F = "particular_properties"
ALL_PPT_F = "all_properties"
logging.basicConfig(level=logging.DEBUG)

def difPpt():
    res = {}
    fn = os.path.join(DATA_PATH, PPT_ENTITY_F + ".json")
    with open(fn, 'r') as fo:
        pptEntity = json.load(fo)
    fn = os.path.join(DATA_PATH, ENTITY_WITH_PPT_F + ".json")
    with open(fn, 'r') as fo:
        entityPpt = json.load(fo)
    logging.debug("Data loaded.")
    for ent in entityPpt.keys():
        newEnt = {}
        for ppt in entityPpt[ent]:
            if ppt in pptEntity:
                newEnt[ppt] = True
            else:
                newEnt[ppt] = False
        res[ent] = newEnt
    fn = os.path.join(DATA_PATH, "dif_" + ENTITY_WITH_PPT_F + ".json")
    with open(fn, 'w') as fo:
        json.dump(res, fo, indent=4)
    logging.debug("Successfully save data in {}".format(fn))
    return True

def particularPpt():
    res = {}
    refPpt = ["object_marking_refs", "created_by_ref", "x_mitre_modified_by_ref",
            "tactic_refs", "external_references", "kill_chain_phases"]
    fn = os.path.join(DATA_PATH, COMMON_PPT_F + ".json")
    with open(fn, 'r') as fo:
        commonPpt = json.load(fo)
    fn = os.path.join(DATA_PATH, ENTITY_WITH_PPT_F + ".json")
    with open(fn, 'r') as fo:
        entityPpt = json.load(fo)
    logging.debug("Data loaded.")
    for ent in entityPpt.keys():
        newEnt = {}
        for ppt in entityPpt[ent]:
            if ppt in commonPpt or ppt in refPpt:
                newEnt[ppt] = False
            else:
                newEnt[ppt] = True
        res[ent] = newEnt
    fn = os.path.join(DATA_PATH, PARTICULAR_PPT_F + ".json")
    with open(fn, 'w') as fo:
        json.dump(res, fo, indent=4)
    logging.debug("Successfully save data in {}".format(fn))
    return True

def findCommonPpt():
    res = []
    fn = os.path.join(DATA_PATH, ENTITY_WITH_PPT_F + ".json")
    with open(fn, 'r') as fo:
        entityPpt = json.load(fo)
    logging.debug("Data loaded.")
    for item in entityPpt["identity"]:
        flag = True
        for ent in entityPpt.keys():
            if ent == "x-mitre-collection" or ent == "relationship" \
            or ent == "marking-definition":
                continue
            if item not in entityPpt[ent]:
                logging.debug("item:{}\t entity:{}".format(item, ent))
                flag = False
        if flag is True:
            res.append(item)
    logging.debug("Common properties: {}".format(res))
    fn = os.path.join(DATA_PATH, COMMON_PPT + ".json")
    with open(fn, 'w') as fo:
        json.dump(res, fo, indent=4)
    logging.debug("Successfully save data in {}".format(fn))
    return True

def allPpt():
    res = {}
    fn = os.path.join(DATA_PATH, "dif_" + ENTITY_WITH_PPT_F + ".json")
    with open(fn, 'r') as fo:
        difEntityPpt = json.load(fo)
    logging.debug("Data loaded.")
    for ent in difEntityPpt.keys():
        for ppt in difEntityPpt[ent].keys():
            if ppt not in res.keys():
                res[ppt] = difEntityPpt[ent][ppt]
    fn = os.path.join(DATA_PATH, ALL_PPT_F + ".json")
    with open(fn, 'w') as fo:
        json.dump(res, fo, indent=4)
    logging.debug("Successfully save data in {}".format(fn))
    return True


def main():
    # difPpt()
    # findCommonPpt()
    # allPpt()
    particularPpt()


if __name__ == "__main__":
    main()
