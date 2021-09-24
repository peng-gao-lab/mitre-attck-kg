# Design and construct TypeDB database
    Software: TypeDB 2.3.3
    Language: TypeQL

## Usage:
### Create database

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
