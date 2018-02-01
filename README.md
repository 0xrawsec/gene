# GENE: Go Evtx sigNature Engine

The idea behind this project is to provide an efficient and standard way to
look into Windows Event Logs (a.k.a EVTX files). For those who are familiar with
Yara, it can be seen as a Yara engine but to look for information into Windows
Events.

Here are some of our motivations:
  1. By doing IR frequently we quickly notice the importance of the information
  we can find inside EVTX files (when they don't get cleared :)).
  2. Some particular events can be considered as IOCs and are sometimes the only
  ones left on the system.
  3. To the best of my knowledge, there is no easy way to query the logs and
  extract directly the interesting events.
    * because we (at least I) never remember all the interesting events
    * we cannot benefit of the other's knowledge
  4. You might tell me, "Yeah! But I push all the interesting events to the SIEM
  and can query them very easily". To what I would reply that it is not that easy.
    * there are events you do not know they exist before you find it in an incident
    so it is very unlikely you push it into your SIEM
    * considering the example of Sysmon logs, it would be quite challenging to push
    everything interesting into your SIEM. Either you have few machines on your
    infra or you are very rich (or at least the company you are working for :)).
  5. Before writing that tool I was always ending up implementing a custom piece
  of software in order to extract the information I needed, which in the end is
  not scalable at all and very time consuming.
  6. I wanted a cross platform tool

# Use Cases

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

# Command line

```
gene: gene -r RULES [OPTIONS] FILES...
  -all
    	Print all events (even the one not matching rules)
  -c int
    	Criticality treshold. Prints only if criticality above threshold
  -cpuprofile string
    	Profile CPU
  -d	Enable debug mode
  -e value
    	Rule file extensions to load (default [.gen .gene])
  -j	Input is in JSON format
  -n value
    	Rule names to match against (comma separated)
  -progress
    	Show progress
  -r string
    	Rule file or directory
  -t value
    	Tags to search for (comma separated)
  -template
    	Prints a rule template
  -trace
    	Tells the engine to use the trace function of the rules
  -ts
    	Show the timestamp of the event when printing
```

# Rule Example

In order not to add an additional layer of parsing to our tool, we decided to rely
on the JSON format. The rules are quite straightforward. You have to respect the
following skeleton if you want the rule to be loaded correctly.

## Simple Rule

Considering the following Sysmon event (converted to JSON)

```json
{
  "Event": {
    "EventData": {
      "Hashes": "SHA1=B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA,MD5=B1A967E26F63F2E78EB1647F3FDA09C4,SHA256=B03C2C4FC1301CE154605290D4F34F3592CEEB8C4190B9FC638FE13D10099439,IMPHASH=05056B92E29CCE6F97F9C6674AE080C0",
      "Image": "C:\\Windows\\SystemApps\\Microsoft.Windows.Cortana_cw5n1h2txyewy\\SearchUI.exe",
      "ImageLoaded": "C:\\Windows\\System32\\DataExchange.dll",
      "ProcessGuid": "B2796A13-E721-5880-0000-00108CCD1C00",
      "ProcessId": "3876",
      "Signature": "Microsoft Windows",
      "Signed": "true",
      "UtcTime": "2017-01-19 16:19:48.448"
    },
    "System": {
      "Channel": "Microsoft-Windows-Sysmon/Operational",
      "Computer": "DESKTOP-5SUA567",
      "Correlation": {},
      "EventID": "7",
      "EventRecordID": "163564",
      "Execution": {
        "ProcessID": "1760",
        "ThreadID": "1956"
      },
      "Keywords": "0x8000000000000000",
      "Level": "4",
      "Opcode": "0",
      "Provider": {
        "Guid": "5770385F-C22A-43E0-BF4C-06F5698FFBD9",
        "Name": "Microsoft-Windows-Sysmon"
      },
      "Security": {
        "UserID": "S-1-5-18"
      },
      "Task": "7",
      "TimeCreated": {
        "SystemTime": "2017-01-19T16:19:48Z"
      },
      "Version": "3"
    }
  }
}

```

We can build up an example rule to match it.

```json
{
"Name": "Foo",
"Tags": ["Bar"],
"Meta": {
  "EventIDs": [1,7],
  "Channels": ["Microsoft-Windows-Sysmon/Operational"],
  "Computers": [],
  "Criticality": 0
  },
"Matches": [
  "$a: Hashes ~= 'B6BCE6C5312EEC2336613FF08F748DF7FA1E55FA'",
  "$b: ImageLoaded = 'C:\\Windows\\System32\\DataExchange.dll'",
  "$c: Signed = 'false'"
  ],
"Condition": "($a or $b) and !$c"
}
```

The above rule is useless and is a showcase just to introduce you the concept.

* The `Meta` part of the rule contains information used to identify the events the rule should apply on. The more precise is this section the quicker the engine is.
  * `Channels` is the list of Windows channels where we can find the events to match the rule against. If empty the rule applies to all channels.
  * `EventIDs` is the list of Event IDs the rule applies on. If empty the rule applies to all event ids.
  * `Computers` is the list of computer names the rule should match on. If empty the rule applies to all events.
  * The `Criticality` is a criticality level attributed to the event matching the rule. If an event matches several rules the `Criticality` fields are added between them.
* The `Matches` contains the different matches you can use later in the `Condition`
* A `Match` is in a form of `$VAR_NAME: OPERAND OPERATOR 'VALUE'`
  * The `OPERAND` is the field in the `EventData` section of the event that will be checked against the `VALUE`
  * So far the `OPERATOR` only applies on `string` so the value cannot by `typed`
  * There are two types of `OPERATOR` for the `Matches`
    * `=` strict match
    * `~=` regexp match (following [Go regexp syntax](https://github.com/google/re2/wiki/Syntax))
* The `Condition` is the logic applied to the `Matches` in order to trigger the rule

NB: The `\` characters have to be escaped while using regexp matches.

# Notes

This project is quite new and may still have little bugs, so do not hesitate to
open issues for those.
