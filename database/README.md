# Design and establish TypeDB database
## Introduction
We establish the TypeDB database by TypeQL language, all the codes can be found in `schema.tql`. We test this database by inserting and reading some simple data items.

## Requirements
    Software: TypeDB 2.3.3
    Language: TypeQL

## Usage:
### Run server
```shell
$ typedb server
```

### Create database

Create a database named `mitre_attack`.

```shell
$ cd ${this_dir} && typedb console

> database create mitre_attack

> transaction mitre_attack schema write

> source schema.tql

> commit
```

### Insert some data

```shell
> transaction mitre_attack data write

> source data.tql

> commit
```

### Simple test

```shell
> transaction mitre_attack data read

> source test.tql
```
