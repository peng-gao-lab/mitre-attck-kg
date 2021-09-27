# group2software

## Introduction
The file in this directory is used to query all the mapping between groups and software, also the types (`tool` or `malware`) of software should be indicated. The result should like that:

```json
{
    ...,
    "Cleaver": {
        "Mimikatz": "tool",
        "Net Crawler": "malware",
        ...
        },
    ...
}
```

## Usage

```shell
$ python3 group2software.py
```
The result is `group2software.json`.