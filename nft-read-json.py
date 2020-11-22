#!/usr/bin/env python3

# (C) 2020 by Arturo Borrero Gonzalez <arturo@netfilter.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This is a code example. This small program uses the libnftables python module
# to read & print the nftables ruleset in the native libnftables JSON format.
# The raw JSON should be the exact same as the one produced by running `nft -j list ruleset`.
#
# To try this, consider creating a couple of objects in nftables first:
#  user@debian:~$ sudo nft add table inet mytable
#  user@debian:~$ sudo nft add chain inet mytable mychain
#  user@debian:~$ sudo nft add rule inet mytable mychain tcp dport {22, 80, 443} counter accept
#
#  user@debian:~$ sudo python3 nft-read-json.py
#   raw libnftables JSON output:
#   {"nftables": [{"metainfo": .......
#   native python data structure:
#   {'nftables': [{'metainfo': .......
#
# More information about nftables: https://wiki.nftables.org and nft(8) manpage
# More information about libnftables JSON: libnftables-json(5) manpage

import nftables
import json


def main():
    # init libnftables
    nft = nftables.Nftables()
    # configure library behavior
    nft.set_json_output(True)
    nft.set_stateless_output(False)
    nft.set_service_output(False)
    nft.set_reversedns_output(False)
    nft.set_numeric_proto_output(True)

    rc, output, error = nft.cmd("list ruleset")
    if rc != 0:
        # do proper error handling here, exceptions etc
        print("ERROR: running cmd 'list ruleset'")
        print(error)
        exit(1)

    if len(output) == 0:
        # more error control
        print("ERROR: no output from libnftables")
        exit(0)

    print("raw libnftables JSON output:\n{}".format(output))

    data_structure = json.loads(output)
    print("native python data structure:\n{}".format(data_structure))


if __name__ == "__main__":
    main()
