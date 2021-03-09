#!/usr/bin/env python3

# (C) 2021 by Arturo Borrero Gonzalez <arturo@netfilter.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This is a code example. This small program uses the libnftables python module
# to load an example nftables ruleset in the native libnftables JSON format.
# The raw JSON should be the exact same as loading the following commands in `nft -f`:
#
# === 8< ===
# flush ruleset
# add table inet mytable
# add chain inet mytable mychain
# add rule inet mytable mychain tcp dport 22 accept
# === 8< ===
#
# To try this example:
#
#  user@debian:~$ sudo python3 nft-load-example-ruleset.py
#  [..]
#  user@debian:~$ sudo nft list ruleset
#  [..]
#
# More information about nftables: https://wiki.nftables.org and nft(8) manpage
# More information about libnftables JSON: libnftables-json(5) manpage

import nftables
import json

# This JSON example was taken from the libnftables-json(5) manpage
NFTABLES_JSON = """
{ "nftables": [
    { "flush": { "ruleset": null } },
    { "add": { "table": {
        "family": "inet",
        "name": "mytable"
    }}},
    { "add": { "chain": {
        "family": "inet",
        "table": "mytable",
        "chain": "mychain"
    }}},
    { "add": { "rule": {
        "family": "inet",
        "table": "mytable",
        "chain": "mychain",
        "expr": [
            { "match": {
                "left": { "payload": {
                    "protocol": "tcp",
                    "field": "dport"
                }},
                "right": 22
            }},
            { "accept": null }
        ]
    }}}
]}
"""


def main():
    nft = nftables.Nftables()

    # STEP 1: load your JSON content
    try:
        data_structure = json.loads(NFTABLES_JSON)
    except json.decoder.JSONDecodeError as e:
        print(f"ERROR: failed to decode JSON: {e}")
        exit(1)

    # STEP 2: validate it with the libnftables JSON schema
    try:
        nft.json_validate(data_structure)
    except Exception as e:
        print(f"ERROR: failed validating json schema: {e}")
        exit(1)

    # STEP 3: finally, run the JSON command
    print(f"INFO: running json cmd: {data_structure}")
    rc, output, error = nft.json_cmd(data_structure)
    if rc != 0:
        # do proper error handling here, exceptions etc
        print(f"ERROR: running json cmd: {error}")
        exit(1)

    if len(output) != 0:
        # more error control?
        print(f"WARNING: output: {output}")

    # ok!
    exit(0)


if __name__ == "__main__":
    main()
