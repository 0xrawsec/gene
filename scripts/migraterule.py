#!/usr/bin/env python

import json
import sys


if __name__ == "__main__":

    failed = []

    for line in sys.stdin.readlines():
        line = line.strip("\n")
        rule = json.loads(line)

        new_meta = {}
        old_meta = rule["Meta"]
        
        # cannot migrate rules with more than one channel
        # because we don't know which event id matches to 
        # which channel (drawback of old rules)
        if len(rule["Meta"]["Channels"]) > 1:
            failed.append(rule["Name"])
            continue
        
        new_meta["Events"] = { rule["Meta"]["Channels"][0]: rule["Meta"]["EventIDs"] }

        for k in old_meta:
            if k not in ["Traces", "Channels", "EventIDs"]:
                new_meta[k] = old_meta[k]

        new_meta["Schema"] = "2.0.0"

        rule["Meta"] = new_meta

        json.dump(rule, sys.stdout, indent=2)
        print()
        print()
    
    for f in failed:
        print(f"Failed at migrating {f}", file=sys.stderr)