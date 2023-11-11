#!/bin/env python

import json
import argparse
import yaml
import sys
import os
import re

class Dumper(yaml.SafeDumper):
    def increase_indent(self, flow=False, *args, **kwargs):
        return super().increase_indent(flow=flow, indentless=False)

def rename_field(camel_case_string):
    # Use regular expression to insert underscore before capital letters
    dash_sep_string = re.sub('([a-z0-9])([A-Z])', r'\1-\2', camel_case_string)
    # Convert the string to lowercase
    dash_sep_string = dash_sep_string.lower()
    return dash_sep_string

def rename_dict_keys(d, parents=""):
    if not isinstance(d, dict):
        return

    if parents in [".match-on.events", ".matches"]:
        return

    for k in [k for k in d.keys()]:
        new_parents = rename_field(f"{parents}.{k}")
        if isinstance(d[k], dict):
            rename_dict_keys(d[k], new_parents)
        if isinstance(d[k], list):
            for e in d[k]:
                rename_dict_keys(e, new_parents)

        new = rename_field(k)
        if new != k:
            d[rename_field(k)] = d[k]
            del(d[k])

if __name__ == "__main__":
    order = ["Name", "Tags", "Params", "MatchOn", "Meta", "Matches", "Condition", "Severity", "Actions"]

    parser = argparse.ArgumentParser()
    parser.add_argument("--format", choices=["json","yaml"], default="json", help="Output format")
    parser.add_argument("RULE_FILE")

    args = parser.parse_args()

    rules = []
    if args.RULE_FILE == "-":
        rules = sys.stdin.readlines()
    elif os.path.isfile(args.RULE_FILE):
        with open(args.RULE_FILE, "r") as fd:
            rules = fd.readlines()

    for r in rules:
        d=json.loads(r)
        new_matches={}

        if "Matches" in d:
            if isinstance(d["Matches"], list):
                # Match format has changed
                for m in d["Matches"]:
                    sp=m.split(":",1)
                    new_matches[sp[0]]=sp[1].lstrip()
                d["Matches"] = new_matches

        # new MatchOn field
        d["MatchOn"]={}
        for k in ["LogType", "Events", "OSs", "Computers"]:
            if "Meta" in d:
                if k not in d["Meta"]:
                    continue
                src, dst = (k, k)
                # Computers gets renamed
                if src == "Computers":
                    dst = "Hostnames"
                d["MatchOn"][dst] = d["Meta"][src]
                del(d["Meta"][src])

        # new params field
        d["Params"]={}
        for k in ["Filter", "Disable"]:
            if "Meta" in d:
                if k not in d["Meta"]:
                    continue
                d["Params"][k] = d["Meta"][k]
                del(d["Meta"][k])
        

        if "Meta" in d:
            # severity has moved out of Meta section
            if "Severity" in d["Meta"]:
                d["Severity"] = d["Meta"]["Severity"]
                del(d[ "Meta"]["Severity"])

            if "Schema" in d["Meta"]:
                # Schema has been removed
                del(d["Meta"]["Schema"])

        # Remove Meta section if empty
        for k in [k for k in d.keys()]:
            if not hasattr(d[k],"__len__"):
                continue
            if len(d[k]) == 0:
                del(d[k])

        ordered = {k:d[k] for k in order if k in d}
        if args.format == "json":
            print(json.dumps(ordered))
        elif args.format == "yaml":
            # we rename keys only if it is yaml output
            rename_dict_keys(ordered)
            yaml.dump(ordered, Dumper=Dumper, explicit_start=True, explicit_end=True, stream=sys.stdout, sort_keys=False)
            print()