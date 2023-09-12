<div align="center"><img src="assets/logo.svg" width="300"/></div>

[![GitHub Workflow Status (with event)](https://img.shields.io/github/actions/workflow/status/0xrawsec/gene/go.yml?style=for-the-badge)](https://github.com/0xrawsec/gene/actions/workflows/go.yml)
![coverage](https://raw.githubusercontent.com/0xrawsec/gene/coverage/.github/badge.svg)
![GitHub tag (with filter)](https://img.shields.io/github/v/tag/0xrawsec/gene?style=for-the-badge&label=version&color=orange)
[![Documentation](https://img.shields.io/badge/docs-latest-blue.svg?style=for-the-badge&logo=docsdotrs)][doc-link]

[doc-link]: https://rawsec.lu/doc/gene/2.0/

# Gene(sis)

A long long time ago (in 2017) after doing many responses to incidents, I realized 
I was always ending up doing the same thing to search inside Windows EVTX logs: 
writting a custom script to match log entries against our findings ! At that moment I
decided to start coding this tool, not only to ease my daily work but also to be able
to share detection rules between parties.

Since then, the tool has evolved and it can now be used to match against
any kind of log (formatted in JSON) and has native support for Windows EVTX parsing.

# Some use cases

  1. Gene can be used to quickly grab interesting information from EVTX at whatever
  stage of analysis.
   * Early compromise information collection
   * Infected host analysis
   * IOC scan on all your machines
  2. If you are forwarding the Windows Event somewhere, you can use it as a
  scheduled task to extract relevant piece of information from those logs.
  3. It can be used to retro search into your EVTX backup
  4. It can be combined with Sysmon in order to build up use cases in a minute
  (the time to write the rule) and it is much more flexible than the Sysmon
  configuration file.
   * Suspicious process spawned by another one
   * Suspicious Driver load events
   * Unusual DLL loaded by a given process
   * ...

# Additional resources
 * To convert old rules (prior to 2.0.0 schema) to the new format, use [migraterule.py](./scripts/migraterule.py)
 * [Where to find rules ?](https://github.com/0xrawsec/gene-rules)

# Changelog

## v2.0.0
  * Code refactoring:
    * Changes in package organisation
    * Changes in API definitions
    * Implementation of an Event interface making APIs more generic
    * Default actions to apply on detections
  * Changes in the rule format:
    * New way define events to apply rule on
    * Schema field to enforce rule format compatibility with engine
    * Removed trace support (not up to date and not used)
  * Regex templates defined in **TOML** format

## v1.6.0
  * Indirect Match Support (we can now compare two fields of the same event)
  * Containers are now case insensitive
  * New `-test` command line switch to create easy Gene unit testing

## v1.5.0
  * Support for Mitre ATT&CK framework
  * Changes in the reducer function
