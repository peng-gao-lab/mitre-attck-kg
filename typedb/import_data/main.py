#! python3
import os, sys, json, logging

sys.path.append("../..")
from configs import *
from stix2 import Filter, MemoryStore
from templates import *
from typedb.client import TypeDB, SessionType, TransactionType
from typedb.common import exception

# Setting
logging.basicConfig(level=logging.DEBUG)
DATA_PATH = os.path.join("../../", "data")
DATABASE_PATH = os.path.join(os.path.pardir, "database")
insert_seq = ["identity", "marking-definition", "x-mitre-tactic", "x-mitre-matrix",
        "attack-pattern", "intrusion-set", "tool", "malware",
        "x-mitre-data-source", "x-mitre-data-component", "course-of-action", "relationship"]


TYPE_TO_TEMPLATE = {
        "identity": identity_template,
        "marking-definition": marking_definition_template,
        "x-mitre-tactic": tactic_template,
        "x-mitre-matrix": matrix_template,
        "attack-pattern": technique_template,
        "intrusion-set": groups_template,
        "tool": software_template,
        "malware": software_template,
        "course-of-action": mitigation_template,
        "relationship": relationships_template,
        "x-mitre-data-source": data_source_template,
        "x-mitre-data-component": data_component_template
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

def combineInsert(matches, inserts):
    res = ''
    if len(matches) > 0:
        res += 'match '
        for match in matches:
            res += match
    if len(inserts) > 0:
        res += 'insert'
        for insert in inserts:
            res += insert
    return res

def insert_element(session, typee, element):
    with session.transaction(TransactionType.WRITE) as transaction:
        matches, inserts = TYPE_TO_TEMPLATE[typee](element)
        insert_query = combineInsert(matches, inserts)
        # logging.debug("Excuting: {}".format(insert_query))
        try:
            transaction.query().insert(insert_query)
            transaction.commit()
        except exception.TypeDBClientException as e:
            logging.warning("There is an TypeDBClientException: {}".format(e.message))
        else:
            # logging.debug("No error")
            pass



# Open session and import data
def import_data(src):
    with TypeDB.core_client("localhost:1729") as client:
        with client.session("mitre_attack", SessionType.DATA) as session:
            for typee in insert_seq:
            # for typee in insert_seq[3:4]:
                query = [Filter("type", "=", typee)]
                elementList = src.query(query)
                # Remove deprecated elements
                elementList = remove_revoked_deprecated(elementList)
                logging.debug("Inserting {} {} elements".format(len(elementList), typee))
                for element in elementList:
                # for element in elementList[:2]:
                    insert_element(session, typee, element)
    logging.debug("Successfully finished!!!")
    return True

def renewDB():
    with TypeDB.core_client("localhost:1729") as client:
        if client.databases().contains("mitre_attack"):
            client.databases().get("mitre_attack").delete()
            logging.debug("Database has been deleted.")
        client.databases().create("mitre_attack")
        logging.debug("Database has been created.")
        with client.session("mitre_attack", SessionType.SCHEMA) as session:
            with session.transaction(TransactionType.WRITE) as transaction:
                filePath = os.path.join(DATABASE_PATH, 'schema.tql')
                with open(filePath, 'r') as fo:
                    defineCode = fo.read()
                    logging.debug("Schema readed")
                transaction.query().define(defineCode)
                transaction.commit()
                logging.debug("Schema define committed")
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
    filePath = os.path.join(DATA_PATH, FILE_NAME + '.json')
    try:
        logging.debug("Loading data from {}".format(filePath))
        src.load_from_file(filePath)
    except BaseException:
        logging.error("Load data error.")
        return
    else:
        logging.debug("Data loaded.")

    renewDB()
    import_data(src)
    return True



if __name__ == "__main__":
    main()
