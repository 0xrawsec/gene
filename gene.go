package main

import (
	"encoding/json"
	"engine"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/args"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/progress"
)

const (
	exitFail    = 1
	exitSuccess = 0
)

var (
	debug         bool
	showTimestamp bool
	allEvents     bool
	showProgress  bool
	inJSONFmt     bool
	tags          []string
	names         []string
	tagsVar       args.ListVar
	namesVar      args.ListVar

	rules    string
	ruleExts = args.ListVar{".gen", ".gene"}
)

func matchEvent(e *engine.Engine, event *evtx.GoEvtxMap) {
	if len(tags) == 0 && len(names) == 0 {
		if n, _ := e.Match(event); len(n) > 0 {
			// Prints out the events with timestamp or not
			if showTimestamp {
				fmt.Printf("%d: %s\n", event.TimeCreated().Unix(), string(evtx.ToJSON(event)))
			} else {
				fmt.Println(string(evtx.ToJSON(event)))
			}
		} else if allEvents {
			if showTimestamp {
				fmt.Printf("%d: %s\n", event.TimeCreated().Unix(), string(evtx.ToJSON(event)))
			} else {
				fmt.Println(string(evtx.ToJSON(event)))
			}
		}

	} else if len(tags) > 0 {
		if n, _ := e.MatchByTag(&tags, event); len(n) > 0 {
			// Prints out the events with timestamp or not
			if showTimestamp {
				fmt.Printf("%d: %s\n", event.TimeCreated().Unix(), string(evtx.ToJSON(event)))
			} else {
				fmt.Println(string(evtx.ToJSON(event)))
			}
		} else if allEvents {
			if showTimestamp {
				fmt.Printf("%d: %s\n", event.TimeCreated().Unix(), string(evtx.ToJSON(event)))
			} else {
				fmt.Println(string(evtx.ToJSON(event)))
			}
		}
	} else if len(names) > 0 {
		if n, _ := e.MatchByNames(&names, event); len(n) > 0 {
			// Prints out the events with timestamp or not
			if showTimestamp {
				fmt.Printf("%d: %s\n", event.TimeCreated().Unix(), string(evtx.ToJSON(event)))
			} else {
				fmt.Println(string(evtx.ToJSON(event)))
			}
		} else if allEvents {
			if showTimestamp {
				fmt.Printf("%d: %s\n", event.TimeCreated().Unix(), string(evtx.ToJSON(event)))
			} else {
				fmt.Println(string(evtx.ToJSON(event)))
			}
		}
	}
}

func main() {
	flag.BoolVar(&debug, "d", debug, "Enable debug mode")
	flag.BoolVar(&showTimestamp, "ts", showTimestamp, "Show the timestamp of the event when printing")
	flag.BoolVar(&allEvents, "all", allEvents, "Print all events (even the one not matching rules)")
	flag.BoolVar(&showProgress, "progress", showProgress, "Show progress")
	flag.BoolVar(&inJSONFmt, "j", inJSONFmt, "Input is in JSON format")
	flag.StringVar(&rules, "r", rules, "Rule file or directory")
	flag.Var(&ruleExts, "e", "Rule file extensions to load")
	flag.Var(&tagsVar, "t", "Tags to search for (comma separated)")
	flag.Var(&namesVar, "n", "Rule names to match against (comma separated)")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s: %[1]s -r RULES [OPTIONS] FILES...\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		os.Exit(0)
	}

	flag.Parse()

	prog := progress.New(128)
	prog.SetPre("Event Processed")

	// Enable debugging mode if needed
	if debug {
		log.InitLogger(log.LDebug)
	}

	// Control parameters
	if rules == "" {
		log.LogErrorAndExit(fmt.Errorf("No rule file to load"), exitFail)
	}

	// Initialization
	e := engine.NewEngine()
	setRuleExts := datastructs.NewSyncedSet()
	tags = []string(tagsVar)
	names = []string(namesVar)

	// Validation
	if len(tags) > 0 && len(names) > 0 {
		log.LogErrorAndExit(fmt.Errorf("Cannot search by tags and names at the same time"), exitFail)
	}

	// Initializes the set of rule extensions
	for _, e := range ruleExts {
		setRuleExts.Add(e)
	}

	// Loading the rules
	realPath, err := fsutil.ResolveLink(rules)
	if err != nil {
		log.LogErrorAndExit(err, exitFail)
	}

	// Handle both rules argument as file or directory
	switch {
	case fsutil.IsFile(realPath):
		err := e.Load(realPath)
		if err != nil {
			log.Error(err)
		}
	case fsutil.IsDir(realPath):
		for wi := range fswalker.Walk(realPath) {
			for _, fi := range wi.Files {
				ext := filepath.Ext(fi.Name())
				rulefile := filepath.Join(wi.Dirpath, fi.Name())
				log.Debug(ext)
				if setRuleExts.Contains(ext) {
					err := e.Load(rulefile)
					if err != nil {
						log.Errorf("Error loading %s: %s", rulefile, err)
					}
				}
			}
		}
	default:
		log.LogErrorAndExit(fmt.Errorf("Cannot resolve %s to file or dir", rules), exitFail)
	}

	log.Infof("Loaded %d rules", e.Count())
	// Scanning the EVTX files
	if !inJSONFmt {
		for _, evtxFile := range flag.Args() {
			eventCnt, cntChunk, oldEventCnt := 0, 100, 100
			ef, err := evtx.New(evtxFile)
			if err != nil {
				log.Error(err)
			}
			// Init Progress
			prog.SetPre(filepath.Base(evtxFile))
			for event := range ef.UnorderedEvents() {
				eventCnt++
				if showProgress && eventCnt >= oldEventCnt {
					prog.Update(fmt.Sprintf("%d", eventCnt))
					prog.Print()
					oldEventCnt = eventCnt + cntChunk
				}
				matchEvent(&e, event)
			}
			log.Infof("Count Event Scanned: %d", eventCnt)
		}
	} else {
		for _, jsonFile := range flag.Args() {
			var f *os.File
			var err error
			eventCnt, cntChunk, oldEventCnt := 0, 100, 100
			if jsonFile != "-" {
				f, err = os.Open(jsonFile)
				if err != nil {
					log.LogError(err)
				}
			} else {
				jsonFile = "stdin"
				f = os.Stdin
			}
			// Setting progress message
			prog.SetPre(filepath.Base(jsonFile))
			d := json.NewDecoder(f)
			for {
				event := evtx.GoEvtxMap{}
				if err := d.Decode(&event); err != nil {
					if err == io.EOF {
						break
					}
					log.LogError(err)
					break
				}
				// Printing Progress
				eventCnt++
				if showProgress && eventCnt >= oldEventCnt {
					prog.Update(fmt.Sprintf("%d", eventCnt))
					prog.Print()
					oldEventCnt = eventCnt + cntChunk
				}
				matchEvent(&e, &event)
			}
			log.Infof("Count Event Scanned: %d", eventCnt)
		}

	}
}
