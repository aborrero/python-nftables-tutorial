#!/usr/bin/env python3

# (C) 2021 by Arturo Borrero Gonzalez <arturo@netfilter.org>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.

# This is a code example. This small program uses the libnftables python module
# to do a few things:
#  * load an example nftables ruleset in the native libnftables JSON format
#  * delete a given rule by searching the handle first, it deletes all rules with a 'counter'
#
# Basically, to delete a few rules we need to know their family, table, chain & handle, and then
# generate a JSON command like this:
# { "nftables": [
#     {"metainfo": {"json_schema_version": 1}},
#     { "delete": { "rule": {
#         "family": "inet",
#         "table": "mytable",
#         "chain": "mychain",
#         "handle": "3"
#     }}},
#     { "delete": { "rule": {
#         "family": "inet",
#         "table": "mytable",
#         "chain": "mychain",
#         "handle": "4"
#     }}}
# ]}
#
# This example program will perform the exact same operation as running the following
# commands.
#
# 1) first, load this ruleset with `nft -f`:
# === 8< ===
# flush ruleset
# add table inet mytable
# add chain inet mytable mychain
# add rule inet mytable mychain udp dport 53 accept
# add rule inet mytable mychain tcp dport 22 counter accept
# add rule inet mytable mychain tcp dport 80 accept
# === 8< ===
#
# 2) list ruleset and search for a rule with a counter, get its handle:
# root@debian:~# HANDLE=$(nft -a list ruleset | grep counter | awk -F'# handle ' '{print $2}')
#
# 3) finally, delete the rule:
# root@debian:~# nft delete rule inet mytable mychain handle $HANDLE
#
# To try this example:
#
#  user@debian:~$ sudo python3 nft-delete-rule.py
#  [..]
#
# More information about nftables: https://wiki.nftables.org and nft(8) manpage
# More information about libnftables JSON: libnftables-json(5) manpage

import nftables
import json

NFTABLES_RULESET_JSON = """
{ "nftables": [
    { "flush": { "ruleset": null } },
    { "add": { "table": {
        "family": "inet",
        "name": "mytable"
    }}},
    { "add": { "chain": {
        "family": "inet",
        "table": "mytable",
        "name": "mychain"
    }}},
    { "add": { "rule": {
        "family": "inet",
        "table": "mytable",
        "chain": "mychain",
        "expr": [
            { "match": {
                "op": "==",
                "left": { "payload": {
                    "protocol": "udp",
                    "field": "dport"
                }},
                "right": 53
            }},
            { "accept": null }
        ]
    }}},
    { "add": { "rule": {
        "family": "inet",
        "table": "mytable",
        "chain": "mychain",
        "expr": [
            { "match": {
                "op": "==",
                "left": { "payload": {
                    "protocol": "tcp",
                    "field": "dport"
                }},
                "right": 22
            }},
            { "counter": null },
            { "accept": null }
        ]
    }}},
    { "add": { "rule": {
        "family": "inet",
        "table": "mytable",
        "chain": "mychain",
        "expr": [
            { "match": {
                "op": "==",
                "left": { "payload": {
                    "protocol": "tcp",
                    "field": "dport"
                }},
                "right": 80
            }},
            { "accept": null }
        ]
    }}}
]}
"""


def load_ruleset(nft):
    try:
        data_structure = json.loads(NFTABLES_RULESET_JSON)
    except json.decoder.JSONDecodeError as e:
        print(f"ERROR: failed to decode JSON: {e}")
        exit(1)

    try:
        nft.json_validate(data_structure)
    except Exception as e:
        print(f"ERROR: failed validating JSON schema: {e}")
        exit(1)

    rc, output, error = nft.json_cmd(data_structure)
    if rc != 0:
        # do proper error handling here, exceptions etc
        print(f"ERROR: running JSON cmd: {error}")
        exit(1)

    if len(output) != 0:
        # more error control?
        print(f"WARNING: output: {output}")


def get_ruleset(nft):
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

    data_structure = json.loads(output)

    try:
        nft.json_validate(data_structure)
    except Exception as e:
        print(f"ERROR: failed validating json schema: {e}")
        exit(1)

    return data_structure


def rule_has_counter(rule: dict):
    for expr in rule["expr"]:
        if expr.get("counter") is not None:
            return True
    return False


def search_rules_with_counter(data_structure: dict):
    ret = []
    for object in data_structure["nftables"]:
        rule = object.get("rule")
        if not rule:
            continue

        if not rule_has_counter(rule):
            continue

        # at this point, we know the rule has a counter expr
        ret.append(
            dict(
                family=rule["family"],
                table=rule["table"],
                chain=rule["chain"],
                handle=rule["handle"],
            )
        )

    return ret


def main():
    nft = nftables.Nftables()
    nft.set_json_output(True)
    nft.set_handle_output(
        True
    )  # important! to get the rule handle when getting the ruleset

    # STEP 1: load the ruleset in JSON format into the kernel
    # see other examples in this tutorial to know more about how this works
    load_ruleset(nft)

    # STEP 2: get the ruleset from the kernel, im JSON format and search for
    # all rules with a 'counter' expression on them, get their information
    kernel_ruleset = get_ruleset(nft)
    info_about_rules_to_delete = search_rules_with_counter(kernel_ruleset)

    # STEP 3: generate a new command to delete all interesting rules, validate and run it
    delete_rules_command = dict(nftables=[])
    delete_rules_command["nftables"] = []
    delete_rules_command["nftables"].append(dict(metainfo=dict(json_schema_version=1)))

    for rule_info in info_about_rules_to_delete:
        delete_rules_command["nftables"].append(dict(delete=rule_info))

    try:
        nft.json_validate(delete_rules_command)
    except Exception as e:
        print(f"ERROR: failed validating JSON schema: {e}")
        exit(1)

    rc, output, error = nft.json_cmd(delete_rules_command)
    if rc != 0:
        # do proper error handling here, exceptions etc
        print(f"ERROR: running JSON cmd: {error}")
        exit(1)

    if len(output) != 0:
        # more error control?
        print(f"WARNING: output: {output}")

    # ok!
    exit(0)


if __name__ == "__main__":
    main()
