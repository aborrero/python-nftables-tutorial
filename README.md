python nftables tutorial
========================

The nftables framework has a native python interface that you can use to interact with the kernel
subsystem without having to call the `nft` binary. This small tutorial shows how to get started
with the nftables library in your python program.

The nftables python module is a native python binding for libnftables, the nftables library that
converts the human-readable syntax into the low level expression that the kernel subsystem runs.

how to use libnftables in python
================================

In Debian systems, the nftables python module is included in the `python3-nftables` package.
Make sure you have it installed before proceeding: `sudo apt install python3-nftables`.

Then, basically, in your code:

* import the nftables module
* init the libnftables instance
* configure library behavior
* run commands and parse the output, ideally using the native JSON format

```
import nftables
import json

nft = nftables.Nftables()
nft.set_json_output(True)
rc, output, error = nft.cmd("list ruleset")
print(json.loads(output))
```

The code above should be equivalent to running `nft -j list ruleset`.

code examples
=============

The best way to learn how to do something is often to follow an example. This repository contains
several python code examples using the libnftables python library and the libnftables JSON format.

more information
================

Check the nftables wiki page: https://wiki.nftables.org

Check the nftables manual page on your system: nft(8)

Check the libnftables-json manual page on your system: libnftables-json(5)

Check related blogpost: https://ral-arturo.org/2020/11/22/python-nftables-tutorial.html
