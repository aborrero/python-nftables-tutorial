#!/usr/bin/env python3

# (C) 2020 by Arturo Borrero Gonzalez <arturo@netfilter.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This is a code example. This small program uses the libnftables python module
# to read & print counters and quotas, using the libnftables JSON output
#
# To try this, consider creating a couple of objects in nftables first:
#  user@debian:~$ sudo nft add table mytable
#  user@debian:~$ sudo nft add counter mytable mycounter
#  user@debian:~$ sudo nft add quota mytable myquota 25 mbytes
#
#  user@debian:~$ sudo python3 nft-read-counters-and-quotas.py
#   Counter "mycounter" in table ip mytable: packets 0 bytes 0
#   Quota "myquota" in table ip mytable: used 0 out of 26214400 bytes (inv: False)
#
# More information about nftables: https://wiki.nftables.org and nft(8) manpage
# More information about libnftables JSON: libnftables-json(5) manpage

import nftables
import json


def _find_objects(ruleset, type):
    # isn't this pure python?
    return [o[type] for o in ruleset if type in o]


def nft_cmd(nftlib, cmd):
    rc, output, error = nftlib.cmd(cmd)
    if rc != 0:
        # do proper error handling here, exceptions etc
        print("ERROR: running cmd {}".format(cmd))
        print(error)
        exit(1)

    if len(output) == 0:
        # more error control
        print("ERROR: no output from libnftables")
        exit(0)

    # transform the libnftables JSON output into generic python data structures
    ruleset = json.loads(output)["nftables"]

    # validate we understand the libnftables JSON schema version.
    # if the schema bumps version, this program might require updates
    for metainfo in _find_objects(ruleset, "metainfo"):
        if metainfo["json_schema_version"] > 1:
            print("WARNING: we might not understand the JSON produced by libnftables")

    return ruleset


def main():
    # init libnftables
    nft = nftables.Nftables()
    # configure library behavior
    nft.set_json_output(True)
    nft.set_stateless_output(False)
    nft.set_service_output(False)
    nft.set_reversedns_output(False)
    nft.set_numeric_proto_output(True)

    # list all nftables stateful counters configured in the system
    ruleset = nft_cmd(nft, "list counters")

    for counter in _find_objects(ruleset, "counter"):
        print(
            'Counter "{}" in table {} {}: packets {} bytes {}'.format(
                counter["name"],
                counter["family"],
                counter["table"],
                counter["packets"],
                counter["bytes"],
            )
        )

    # list all nftables quota objects configured in the system
    ruleset = nft_cmd(nft, "list quotas")

    for quota in _find_objects(ruleset, "quota"):
        print(
            'Quota "{}" in table {} {}: used {} out of {} bytes (inv: {})'.format(
                quota["name"],
                quota["family"],
                quota["table"],
                quota["used"],
                quota["bytes"],
                quota["inv"],
            )
        )


if __name__ == "__main__":
    main()
