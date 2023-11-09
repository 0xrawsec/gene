package template

var (
	RuleTemplate = `---
# rule name, this is the only mandatory field
name: RuleName
params:
  filter: false
  disable: false
match-on:
  log-type: winevt
  events:
    SomeEventSource: [1, 2, 42]
  oss:
    - linux
    - windows
  computers: []
meta:
  attack:
    - id: T4242
      tactic: ''
      reference: https://attack.mitre.org/T4242
  authors:
    - '@0xrawsec'
  comments:
    - Rule catching technique documented in the following link
    - https://super.ttp.com
matches:
  $a: SomeField = '42'
  $b: /Absolute/Field/Path ~= 'SomeRegex'
condition: $a or $b
severity: 5
...`
)
