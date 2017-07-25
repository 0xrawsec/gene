package main

import (
	"engine"
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/args"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/golang-utils/log"
)

const (
	exitFail    = 1
	exitSuccess = 0
)

var (
	debug         bool
	showTimestamp bool

	rules    string
	ruleExts = args.ListVar{".gen", ".gene"}
)

func main() {
	flag.BoolVar(&debug, "d", debug, "Enable debug mode")
	flag.BoolVar(&showTimestamp, "t", showTimestamp, "Show the timestamp of the event when printing")
	flag.StringVar(&rules, "r", rules, "Rule file or directory")
	flag.Var(&ruleExts, "e", "Rule file extensions to load")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s: %[1]s -r RULES [OPTIONS] FILES...\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		os.Exit(0)
	}

	flag.Parse()

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
						log.Error(err)
					}
				}
			}
		}
	default:
		log.LogErrorAndExit(fmt.Errorf("Cannot resolve %s to file or dir", rules), exitFail)
	}

	log.Infof("Loaded %d rules", e.Count())

	// Scanning the EVTX files
	for _, evtxFile := range flag.Args() {
		ef, err := evtx.New(evtxFile)
		if err != nil {
			log.Error(err)
		}
		for event := range ef.FastEvents() {
			if n, _ := e.Match(event); len(n) > 0 {
				// Prints out the events with timestamp or not
				if showTimestamp {
					fmt.Printf("%d: %s\n", event.TimeCreated().Unix(), string(evtx.ToJSON(event)))
				} else {
					fmt.Println(string(evtx.ToJSON(event)))
				}
			}
		}
	}
}
