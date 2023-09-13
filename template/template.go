package template

var (
	RuleTemplate = `
{
  "Name": "RuleName",
  "Tags": [],
  "Meta": {
    "LogType": "winevt",
    "Events": {
      "SomeEventSource": [
        42
      ]
    },
    "OSs": [
      "linux",
      "windows"
    ],
    "Computers": [],
    "ATTACK": [
      {
        "ID": "T4242",
        "Tactic": "",
        "Reference": "https://attack.mitre.org/T4242"
      }
    ],
    "Criticality": 5,
    "Disable": false,
    "Filter": false,
    "Schema": "2.0.0",
    "Authors": [
      "@rawsec"
    ],
    "Comments": [
      "Rule catching technique documented in the following link",
      "https://super.ttp.com"
    ]
  },
  "Matches": [
    "$a: SomeField = '42'",
    "$b: /Absolute/Field/Path ~= 'SomeRegex'"
  ],
  "Condition": "$a or $b",
  "Actions": []
}
	`
)
