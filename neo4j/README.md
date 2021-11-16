# Design and establish neo4j database
## Introduction
We establish the neo4j database by py2neo, all the codes can be found in `schema.py`.

## Requirements
```
python3
python packages: py2neo stix2
```

## Usage:
### Run server
```shell
$ neo4j start
```

### Insert the data in ../data/enterprise.10.json to database

```shell
$ python import_data.py
```
