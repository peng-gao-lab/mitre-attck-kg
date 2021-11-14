#! python3
import os, sys, json, logging

sys.path.append("../..")
from configs import *
from typedb.client import TypeDB, SessionType, TransactionType
from typedb.common import exception

logging.basicConfig(level=logging.INFO)
group2software = os.path.join(os.path.pardir, "group2software")
filePath = os.path.join(group2software, "group2software.json")


def main():
    with TypeDB.core_client("localhost:1729") as client:
        with client.session("mitre_attack", SessionType.DATA) as session:
            with session.transaction(TransactionType.READ) as transaction:
                ## Output the mapping between groups and software
                query = '''
                    match
                    $groups isa groups, has name $gname;
                    $software isa software, has name $sname;
                    (user: $groups, used: $software) isa use;
                    get $gname, $sname;
                '''
                logging.info("Executing: {}".format(query))
                answers = transaction.query().match(query)
                with open(filePath, 'r') as fo:
                    data = json.load(fo)
                    logging.info("Item number: {}".format(len(data.keys())))
                    count = 0
                    for answer in answers:
                        # breakpoint()
                        gname = answer.get("gname").get_value()
                        sname = answer.get("sname").get_value()
                        logging.debug("Group: {}, Software: {}".format(gname, sname))
                        if gname in data.keys() and sname in data[gname].keys():
                            pass
                        else:
                            count += 1
                            logging.warn("Group: {}, Software: {} do not exist in file.".format(gname, sname))
    logging.info("Count: {}".format(count))
    logging.info("Successfully finished!!!")


if __name__ == "__main__":
    main()
