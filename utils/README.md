# ATTACK databases statistics
## Introduction
The source file `../data/enterprise-attacks` comes from [attack-stix-data](https://github.com/mitre-attack/attack-stix-data/tree/master/enterprise-attack). We do some counting work in this directory:

- Collect all entities
- Collect all properties
- Collect all relationships
- Collect all the mapping between entities and properties
- ...

## usage

```shell
python3 collect.py

python3 pro2db.py
```

The results will store in `../data/`
