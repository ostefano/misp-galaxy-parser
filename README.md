# MISP Galaxy Parser

Utilities to parse galaxy clusters and resolve labels (including synonyms).

There is some string normalization (whitespace removal and compound words handling) that 
can be improved, but anything domain-specific is computed using MITRE galaxies.

```bash
./bin/query_galaxy.py -q sednit -g mitre-intrusion-set 
> Mapping 'sednit' to:  ['misp-galaxy:mitre-intrusion-set="APT28 - G0007"']
```

```bash
./bin/query_galaxy.py -q apt28 -g mitre-intrusion-set 
> Mapping 'apt28' to:  ['misp-galaxy:mitre-intrusion-set="APT28 - G0007"']
```

```bash
./bin/query_galaxy.py -q feodo -g malpedia
> Mapping 'feodo' to:  ['misp-galaxy:malpedia="Emotet"']
```

```bash
./bin/query_galaxy.py -q emotet -g malpedia
> Mapping 'emotet' to:  ['misp-galaxy:malpedia="Emotet"']
```