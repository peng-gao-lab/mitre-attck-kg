#!python3
import os, sys, logging, json

sys.path.append("..")
from configs import *
from stix2 import MemoryStore, Filter

# Setting
DATA_PATH = os.path.join(os.path.pardir, "data")
logging.basicConfig(level=logging.DEBUG)

# Get all data
def getAllData(src):
    query = [Filter("spec_version", "=", "2.1")]
    allData = src.query(query)
    logging.info("Total items number: {}".format(len(allData)))
    return allData

# Get all the available STIX type
def getEntity(src):
    allData = getAllData(src)
    for data in allData:
        if data["type"] not in MAIN_ENTITY:
            MAIN_ENTITY.append(data["type"])
        for key in data.keys():
            if type(data[key]) is list:
                if type(data[key][0]) is dict and key not in LEVEL2_PPT:
                    LEVEL2_PPT.append(key)
                if key not in PPT_ENTITY:
                    PPT_ENTITY.append(key)
    logging.debug("All main entity types:\nNumber:{}\nList:{}".format(len(MAIN_ENTITY), MAIN_ENTITY))
    logging.debug("All property entity types:\nNumber:{}\nList:{}".format(len(PPT_ENTITY), PPT_ENTITY))
    logging.debug("Level-2 propertities: {}".format(LEVEL2_PPT))
    return True

def getProperties(src):
    # Initiate level-2 properties
    for ppt in LEVEL2_PPT:
        LEVEL2_PPT_WITH_PPT[ppt] = []
    for t in MAIN_ENTITY:
        properties = []
        query = [Filter("type", "=", t)]
        data = src.query(query)
        # Find all unique properties of an entity
        for d in data:
            # Traverse all properties
            for key in d.keys():
                # Level-2 properties also have their own properties
                if key in LEVEL2_PPT:
                    for d2 in d[key]:
                        for key2 in d2.keys():
                            if key2 not in LEVEL2_PPT_WITH_PPT[key]:
                                LEVEL2_PPT_WITH_PPT[key].append(key2)
                # Main entities
                if key not in properties:
                    properties.append(key)
        ENTITY_WITH_PPT[t] = properties
        logging.debug("Entity {} has {} properties".format(t, len(properties)))
    for ppt in LEVEL2_PPT:
        logging.debug("Level2 property {} has {} properties".format(ppt, len(LEVEL2_PPT_WITH_PPT[ppt])))
    logging.info("Get {} entities' properties".format(len(ENTITY_WITH_PPT)))
    return True

# Get all relationships
def getAllRelat(src):
    query = [Filter("type", "=", "relationship")]
    allRelat = src.query(query)
    logging.info("Total relationship items number: {}".format(len(allRelat)))
    return allRelat

# Get all used relationship type in ATTACK databases
def getRelatType(src):
    allRelat = getAllRelat(src)
    for relat in allRelat:
        # triple. e.g.,(malware => uses => attack-pattern)
        uniqRelat = []
        uniqRelat.append(relat["source_ref"].split("--")[0])
        uniqRelat.append(relat["relationship_type"])
        uniqRelat.append(relat["target_ref"].split("--")[0])
        if uniqRelat not in RELAT_TYPE:
            RELAT_TYPE.append(uniqRelat)
    logging.debug("All relationship types: {}".format(RELAT_TYPE))
    return True

def printRelation(relatData):
    for relat in relatData:
        print("{}\t=>\t{}\t=>\t{}\n".format(relat[0], relat[1], relat[2]))
    return True

def saveStatistic():
    # Save unique entities
    fn = os.path.join(DATA_PATH, MAIN_ENTITY_F + ".json")
    with open(fn, 'w') as fo:
        json.dump(MAIN_ENTITY, fo, indent=4)
    fn = os.path.join(DATA_PATH, PPT_ENTITY_F + ".json")
    with open(fn, 'w') as fo:
        json.dump(PPT_ENTITY, fo, indent=4)
    # Save relationship types
    fn = os.path.join(DATA_PATH, RELAT_TYPE_F + ".json")
    with open(fn, 'w') as fo:
        json.dump(RELAT_TYPE, fo, indent=4)
    fn = os.path.join(DATA_PATH, ENTITY_WITH_PPT_F + ".json")
    # Save entities with relationships
    with open(fn, 'w') as fo:
        json.dump(ENTITY_WITH_PPT, fo, indent=4)
    fn = os.path.join(DATA_PATH, LEVEL2_PPT_WITH_PPT_F + ".json")
    with open(fn, 'w') as fo:
        json.dump(LEVEL2_PPT_WITH_PPT, fo, indent=4)


def main():
    # Load data from enterprise.json
    src = MemoryStore(allow_custom=True)
    filePath = os.path.join(DATA_PATH, FILE_NAME + ".json")
    try:
        logging.debug("Loading data from {}".format(filePath))
        src.load_from_file(filePath)
    except BaseException:
        logging.error("Load data error.")
        return
    else:
        logging.debug("Data loaded.")

    getEntity(src)
    getProperties(src)
    getRelatType(src)
    # printRelation(RELAT_TYPE)
    saveStatistic()


if __name__ == "__main__":
    main()
