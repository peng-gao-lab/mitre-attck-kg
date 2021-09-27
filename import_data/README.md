# Import data from enterprise-attack to TypeDB database
## Introduction
We should import data after the database is established, please refer to [database](../database). This TypeDB database has been named `mitre_attack`.

We use [python API](https://docs.vaticle.com/docs/client-api/python) offered by TypeDB to insert and query database. 

In the `templates.py` file, we define templates of all entities and relations, This is part of technique template:

```python
def technique_template(technique):
    # Common properties
    temp = ' $technique isa technique, has id "' + technique["id"] + '"'
    temp += addStr(technique, "types")
    temp += addStr(technique, "name")
    temp += addStr(technique, "spec_version")
    temp += addDate(technique, "created")
    temp += addDate(technique, "modified")
    temp += addStr(technique, "x_mitre_version")
    temp += addList(technique, "x_mitre_domains")
```

This is an example of reference relations template:

```python
def object_marking_ref_template(source, tids):
    matches = []
    inserts = []
    for tid in tids:
        matches.append(' $mdtarget isa marking-definition, has id "' + tid + '";')
        inserts.append(" (marked: ${}, ref: $mdtarget) isa object_marking_refs;".format(source))
    return matches, inserts
```

This is part of relationships template:
```python
def relationships_template(relation):
    matches = []
    inserts = []
    stype, sid, ttype, tid, rtype = parseRelationship(relation)

    matches.append(' $source isa {}, has id "{}";'.format(stype, sid))
    matches.append(' $target isa {}, has id "{}";'.format(ttype, tid))

    inserts.append(' $relat ({}: $source, {}: $target) isa {}'.format(RELATION_ACTORS_MAPPING[rtype][0], RELATION_ACTORS_MAPPING[rtype][1], rtype))
    inserts.append(addCommonPpts(relation))
```

In `main.py`, we load and parse `enterprise-attack.json` by `stix2`, then insert the parsed data into the database by putting every object in its corresponding template.

We also validate the correctness of this database in `test.py`. We compare the [groups2software](../groups2software) result with the results of the following query:
```
match
$groups isa groups, has name $gname;
$software isa software, has name $sname;
(user: $groups, used: $software) isa use;
get $gname, $sname;
```
The result show that they match well.

## Usage

```shell
### import data
$ python3 main.py

### test
$ python3 test.py
```