# mitre-attack-kg

## Introduction
[MITRE ATT&CK](https://attack.mitre.org/) provides a lot of useful knowledge about adversary tactics, techniques, and tools. In order to make full use of this knowledge base, we establish a graph database and look forward to some new insights into attack affairs.

This repository mainly achieves two goals: 
- Establishing a graph database.
- Importing data.


## Contents
```
|-- {Current directory}
    |-- data            #Source, result and intermediate files.
    |-- database        #TypeDB database establishment.
    |-- import_data     #Importing data from source file to database.
    |-- groups2software #Query the mapping between groups and software.
    |-- utils           #Statistics of source data file.
```

## Requirements
```
Software and Tools: TypeDB, Python3, TypeDB Studio (for visualization)

Python3 Packages: stix2, typedb-client
```