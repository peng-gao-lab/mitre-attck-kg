#! python3
import os, sys, logging
import schema as S

from py2neo import Graph, Subgraph
from stix2 import Filter, MemoryStore
sys.path.append("..")
from configs import *

# Setting
logging.basicConfig(level=logging.INFO)

DATA_PATH = os.path.join("../", "data")
DATABASE_PATH = os.path.join(os.path.pardir, "database")
insert_seq = ["identity", "marking-definition", "x-mitre-tactic", "x-mitre-matrix",
        "attack-pattern", "intrusion-set", "tool", "malware",
        "x-mitre-data-source", "x-mitre-data-component", "course-of-action", "relationship"]

TYPE_TO_CLASS = {
        "identity": S.Identity,
        "marking-definition": S.MarkingDefinition,
        "x-mitre-tactic": S.Tactic,
        "x-mitre-matrix": S.Matrix,
        "attack-pattern": S.Technique,
        "intrusion-set": S.Group,
        "tool": S.Software,
        "malware": S.Software,
        "course-of-action": S.Mitigation,
        "x-mitre-data-source": S.DataSource,
        "x-mitre-data-component": S.DataComponent
        }

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

# Connect neo4j database
def get_connected_graph():
    host = "localhost"
    port = "7687"
    user = "neo4j"
    passwd = "12344321"
    url = f"bolt://{host}:{port}"
    graph = Graph(url, auth=(user, passwd))
    logging.info("Connected to neo4j database")
    return graph

def renewDB(graph):
    logging.info("Deleting data from database")
    graph.delete_all()
    return True

# import element
def import_element(graph, typee, element):
    if typee == "relationship":
        nodes = S.addRelat(graph, element)
    else:
        node = TYPE_TO_CLASS[typee]()
        node.add_properties(element)
        nodes = node.add_relations(graph, element)
        nodes.append(node)
    push_nodes(graph, nodes)
    return True

# import data to neo4j database
def import_data(src, graph):
    for typee in insert_seq:
    # for typee in insert_seq[3:4]:
        query = [Filter("type", "=", typee)]
        elementList = src.query(query)
        # Remove deprecated elements
        elementList = remove_revoked_deprecated(elementList)
        logging.info("Inserting {} {} elements".format(len(elementList), typee))
        for element in elementList:
        # for element in elementList[:2]:
            import_element(graph, typee, element)
    logging.info("Successfully finished!!!")
    return True

# Load data from json file
def load_data(src):
    filePath = os.path.join(DATA_PATH, FILE_NAME + '.json')
    try:
        logging.info("Loading data from {}".format(filePath))
        src.load_from_file(filePath)
    except BaseException:
        logging.error("Load data error.")
        return False
    else:
        logging.info("Data loaded.")
    return True

# Push node to neo4j database
def push_nodes(graph, nodes):
    assert isinstance(graph, Graph)
    tx = graph.begin()
    for n in [i for i in nodes if i != None]:
        tx.push(n)
    graph.commit(tx)
    return True

def import_test(graph):
    logging.info("Importing test data")
    res = S.test()
    push_nodes(graph, res)
    return True

# Load data from source file and import data to database
def main():
    # 1. Insert identity
    # 2. Insert marking-definition -> add relations with identity
    # 3. Insert technique -> add relations with identity and marking-dinifinition
    # 4. software -> add relations with all above
    # 5. groups -> ...
    # 6. ...
    # If one entity has kill_chain_phases or external_references propertities, then add corresponding entities

    # Read data from enterprise-attack
    src = MemoryStore(allow_custom=True)
    if not load_data(src):
        return False

    graph = get_connected_graph()
    renewDB(graph)
    # import_test(graph)
    import_data(src, graph)
    return True


if __name__ == "__main__":
    main()
