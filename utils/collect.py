#!python3
import os, sys, logging

sys.path.append("..")
from configs import *
from stix2 import MemoryStore, Filter

logging.basicConfig(level=logging.INFO)

# Get all data
def getAllData(src):
    query = [Filter("modified", "<", "2021-09-20T21:33:10.772474Z")]
    allData = src.query(query)
    logging.info("Total items number: {}".format(len(allData)))
    return allData

# Get all the available STIX type
def getType(src):
    allData = getAllData(src)
    for data in allData:
        if data["type"] not in TYPE:
            TYPE.append(data["type"])
    logging.info("All type: {}".format(TYPE))
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
        if uniqRelat not in RELATIONSHIP_TYPE:
            RELATIONSHIP_TYPE.append(uniqRelat)
    logging.debug("All relationship types: {}".format(RELATIONSHIP_TYPE))
    return True

def printRelation(relatData):
    for relat in relatData:
        print("{}\t=>\t{}\t=>\t{}\n".format(relat[0], relat[1], relat[2]))
    return True


def main():
    # Load data from enterprise.json
    src = MemoryStore(allow_custom=True)
    filePath = ROOT + "/../data/" + FILE_NAME + ".json"
    try:
        logging.debug("Loading data from {}".format(filePath))
        src.load_from_file(filePath)
    except BaseException:
        logging.error("Load data error.")
        return
    else:
        logging.debug("Data loaded.")

    getType(src)
    getRelatType(src)
    printRelation(RELATIONSHIP_TYPE)


if __name__ == "__main__":
    main()
