#!/usr/bin/env python2
# -*- coding: utf-8 -*-
"""
Dump EV certs SHA1 from the firefox nsIdentityChecking.cpp source file.

WARNING: the first entry and last entries of the EV list are for debug purpose.
"""
from __future__ import print_function

import re
import sys

PATTERN = re.compile(":".join(["([0-9A-F]{2})"] * 20))

def extract_ev_sha1(filename):
    with open(filename) as f:
        for match in PATTERN.finditer(f.read()):
            sha1 = "".join(match.groups()).lower()
            yield sha1

if __name__ == "__main__":
    ev_certs = list(extract_ev_sha1(sys.argv[1]))
    # XXX filter out debug certs
    for sha1 in ev_certs[1:-1]:
        print(sha1)
