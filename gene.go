package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"
	"sync"
	"time"

	"github.com/0xrawsec/gene/v2/engine"
	"github.com/0xrawsec/gene/v2/reducer"
	"github.com/0xrawsec/gene/v2/template"
	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/args"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/progress"
	"github.com/0xrawsec/golang-utils/readers"
)

//////////////////////////// Utilities //////////////////////////////

func matchEvent(e *engine.Engine, evt engine.Event) {
	mr := e.Match(evt)
	// if we don't want to display filtered events
	if flNoFilter && mr.IsOnlyFiltered() {
		return
	}

	// We print only if we are not in test mode
	if (mr.IsDetection() || mr.IsOnlyFiltered()) && !flTest {
		// Prints out the events with timestamp or not
		if mr.Severity >= severityTresh || mr.IsOnlyFiltered() {
			if flShowTimestamp {
				fmt.Printf("%d: %s\n", evt.Timestamp().Unix(), string(evtx.ToJSON(evt)))
				return
			}
			fmt.Println(string(evtx.ToJSON(evt)))
		}
	} else if flAllEvents || (flTest && !mr.IsDetection()) {
		// if we print all events or if we are in test mode and this is not a detection
		if flShowTimestamp {
			fmt.Printf("%d: %s\n", evt.Timestamp().Unix(), string(evtx.ToJSON(evt)))
			return
		}
		fmt.Println(string(evtx.ToJSON(evt)))
	}
}

func jsonEventGenerator() (ec chan *evtx.GoEvtxMap) {
	ec = make(chan *evtx.GoEvtxMap)
	prog := progress.New(128)
	prog.SetPre("Event Processed")

	go func() {
		defer close(ec)
		eventCnt, cntChunk, oldEventCnt := 0, 100, 100
		for _, jsonFile := range flag.Args() {
			var f *os.File
			var err error
			if jsonFile != "-" {
				log.Infof("Processing: %s", jsonFile)
				f, err = os.Open(jsonFile)
				if err != nil {
					log.Error(err)
				}
			} else {
				jsonFile = "stdin"
				f = os.Stdin
			}
			// Setting progress message
			prog.SetPre(filepath.Base(jsonFile))
			d := json.NewDecoder(f)
			start := time.Now()
			for {
				event := evtx.GoEvtxMap{}
				if err := d.Decode(&event); err != nil {
					if err == io.EOF {
						break
					}
					log.Error(err)
					break
				}
				// Printing Progress
				eventCnt++
				if flShowProgress && eventCnt >= oldEventCnt {
					delta := time.Since(start)
					prog.Update(fmt.Sprintf("%d (%2.f EPS)", eventCnt, float64(eventCnt)/delta.Seconds()))
					prog.Print()
					oldEventCnt = eventCnt + cntChunk
				}
				//matchEvent(&e, &event)
				ec <- &event
			}
			//log.Infof("Count Rules Used (loaded + generated): %d", e.Count())
		}
	}()
	return
}

func evtxEventGenerator() (ec chan *evtx.GoEvtxMap) {
	ec = make(chan *evtx.GoEvtxMap)
	prog := progress.New(128)
	prog.SetPre("Event Processed")
	go func() {
		defer close(ec)
		eventCnt, cntChunk, oldEventCnt := 0, 100, 100
		for _, evtxFile := range flag.Args() {
			log.Infof("Processing: %s", evtxFile)
			ef, err := evtx.OpenDirty(evtxFile)
			if err != nil {
				log.Error(err)
			}
			// Init Progress
			prog.SetPre(filepath.Base(evtxFile))
			start := time.Now()
			for event := range ef.UnorderedEvents() {
				eventCnt++
				if flShowProgress && eventCnt >= oldEventCnt {
					delta := time.Since(start)
					prog.Update(fmt.Sprintf("%d (%2.f EPS)", eventCnt, float64(eventCnt)/delta.Seconds()))
					prog.Print()
					oldEventCnt = eventCnt + cntChunk
				}
				//matchEvent(&e, event)
				ec <- event

			}
		}
	}()
	return
}

func printInfo(writer io.Writer) {
	fmt.Fprintf(writer, "Version: %s\nCommit: %s\nCopyright: %s\nLicense: %s\n\n", version, commitID, copyright, license)

}

var (
	sigPath      = evtx.Path("/Event/GeneInfo/Signature")
	computerPath = evtx.Path("/Event/System/Computer")
)

func reduce(e *engine.Engine) {
	reducer := reducer.NewReducer(e)
	wg := sync.WaitGroup{}
	events := jsonEventGenerator()
	for i := 0; i < jobs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for e := range events {
				computer, err := e.GetString(&computerPath)
				if err != nil {
					continue
				}

				iArray, err := e.Get(&sigPath)
				if err != nil {
					continue
				}

				sigs := make([]string, 0, len((*iArray).([]interface{})))
				for _, s := range (*iArray).([]interface{}) {
					sigs = append(sigs, s.(string))
				}

				reducer.Update(e.TimeCreated(), computer, sigs)
			}
		}()
	}
	wg.Wait()
	reducer.Print()
}

/////////////////////////////// Main //////////////////////////////////

const (
	exitFail    = 1
	exitSuccess = 0
	copyright   = "Gene Copyright (C) 2017 RawSec SARL (@0xrawsec)"
	license     = "License GPLv3: This program comes with ABSOLUTELY NO WARRANTY.\nThis is free software, and you are welcome to redistribute it under certain conditions;"
)

var (
	flDebug         bool
	flShowTimestamp bool
	flAllEvents     bool
	flShowProgress  bool
	flJSONFormat    bool
	flTemplate      bool
	flVerify        bool
	flListTags      bool
	flVersion       bool
	flReduce        bool
	flShowAttack    bool
	flTest          bool
	flNoFilter      bool

	cpuprofile string
	tags       []string
	names      []string
	tagsVar    args.ListVar
	namesVar   args.ListVar
	dumpsVar   args.ListVar

	severityTresh int

	whitelist string
	blacklist string

	rulesPath string
	ruleExts  = args.ListVar{".gen", ".gene"}
	jobs      = 1

	// set with -ldflags at compile time
	version  string
	commitID string
)

func main() {
	flag.BoolVar(&flDebug, "debug", flDebug, "Enable debug mode")
	flag.BoolVar(&flShowTimestamp, "t", flShowTimestamp, "Show the timestamp of the event when printing")
	flag.BoolVar(&flAllEvents, "all", flAllEvents, "Print all events (even the one not matching rules)")
	flag.BoolVar(&flShowProgress, "progress", flShowProgress, "Show progress")
	flag.BoolVar(&flJSONFormat, "j", flJSONFormat, "Input is in JSON format")
	flag.BoolVar(&flTemplate, "template", flTemplate, "Prints a rule template")
	flag.BoolVar(&flVerify, "verify", flVerify, "Verify the rules and exit")
	flag.BoolVar(&flListTags, "list-tags", flListTags, "List tags of rules loaded into the engine")
	flag.BoolVar(&flVersion, "version", flVersion, "Show version information and exit")
	flag.BoolVar(&flReduce, "reduce", flReduce, "Aggregate the results of already processed events and outputs condensed information")
	flag.BoolVar(&flShowAttack, "a", flShowAttack, "Show Mitre ATT&CK information in matching events")
	flag.BoolVar(&flTest, "test", flTest, "Test mode. Prints non matching events and returns a non zero status code if not all events match")
	flag.BoolVar(&flNoFilter, "no-filter", flNoFilter, "Don't display filtered events")
	flag.StringVar(&rulesPath, "r", rulesPath, "Rule file or directory")
	flag.StringVar(&cpuprofile, "cpuprofile", cpuprofile, "Profile CPU")
	flag.StringVar(&whitelist, "whitelist", whitelist, "File containing values to insert into the whitelist")
	flag.StringVar(&blacklist, "blacklist", blacklist, "File containing values to insert into the blacklist")
	flag.IntVar(&severityTresh, "s", severityTresh, "Severity treshold. Prints only if severity above threshold")
	flag.IntVar(&jobs, "jobs", jobs, "Number of parallel jobs to run. It may result in events printed in different order than provided (use -t to print timestamp and re-order). If <= 0 takes all available processors")
	flag.Var(&ruleExts, "e", "Rule file extensions to load")
	flag.Var(&tagsVar, "tags", "Tags to select rules to compile (comma separated)")
	flag.Var(&namesVar, "n", "Rule names to match against (comma separated)")
	flag.Var(&dumpsVar, "dump", "Dumps the rules matching the regex provided (comma separated) and then exits. Usefull to verify if regexp template is correctly applied")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s: %[1]s -r RULES [OPTIONS] FILES...\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		os.Exit(0)
	}

	flag.Parse()

	if cpuprofile != "" {
		f, err := os.Create(cpuprofile)
		if err != nil {
			log.Abort(exitFail, err)

		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	// Enable debugging mode if needed
	if flDebug {
		log.InitLogger(log.LDebug)
	}

	// If version switch
	if flVersion {
		printInfo(os.Stderr)
		os.Exit(exitSuccess)
	}

	// Handling job parameter
	// If jobs is not in affordable range
	if jobs <= 0 || jobs > runtime.NumCPU() {
		jobs = runtime.NumCPU()

	}

	// Display rule template and exit if template flag
	if flTemplate {
		fmt.Println(string(template.RuleTemplate))
		os.Exit(exitSuccess)
	}

	// Control parameters
	if rulesPath == "" {
		log.Abort(exitFail, "No rule file to load")
	}

	// Initialization
	e := engine.NewEngine()
	setRuleExts := datastructs.NewSyncedSet()
	tags = []string(tagsVar)
	names = []string(namesVar)
	// Enable rule dumping on engine side
	e.SetDumpRaw(len(dumpsVar) > 0)
	// Enable showing Mitre ATT&CK information
	e.SetShowAttck(flShowAttack)

	// Validation
	if len(tags) > 0 && len(names) > 0 {
		log.Abort(exitFail, "Cannot search by tags and names at the same time")
	}
	e.SetFilters(names, tags)

	// Initializes the set of rule extensions
	for _, e := range ruleExts {
		setRuleExts.Add(e)
	}

	// We have to load the containers befor the rules
	// For the Whitelist
	if whitelist != "" {
		wlf, err := os.Open(whitelist)
		if err != nil {
			log.Abort(exitFail, err)
		}
		for line := range readers.Readlines(wlf) {
			e.Whitelist(string(line))
		}
		wlf.Close()
	}
	log.Infof("Size of whitelist container: %d", e.WhitelistLen())
	// For the Blacklist
	if blacklist != "" {
		blf, err := os.Open(blacklist)
		if err != nil {
			log.Abort(exitFail, err)
		}
		for line := range readers.Readlines(blf) {
			e.Blacklist(string(line))
		}
		blf.Close()
	}
	log.Infof("Size of blacklist container: %d", e.BlacklistLen())

	// Loading the rules and templates
	// we first prepare the rules path
	realPath, err := fsutil.ResolveLink(rulesPath)
	if err != nil {
		log.Abort(exitFail, err)
	}

	// actual rule loading
	if err := e.LoadDirectory(realPath); err != nil {
		log.Abort(exitFail, fmt.Errorf("failed at loading rule directory %s: %s", realPath, err))
	}

	// Show message about successfuly compiled rules
	log.Infof("Loaded %d rules", e.Count())

	// If we just wanted to verify the rules, we should exit whatever
	// the status of the compilation
	if flVerify {
		log.Infof("Rule(s) compilation: SUCCESSFUL")
		os.Exit(exitSuccess)
	}

	// If we want to reduce
	if flReduce {
		reduce(e)
		os.Exit(exitSuccess)
	}

	// If we want to dump rules
	if len(dumpsVar) > 0 {
		for _, nameRegex := range dumpsVar {
			for json := range e.GetRawRule(nameRegex) {
				fmt.Println(json)
			}
		}
		os.Exit(exitSuccess)
	}

	// If we list the tags available
	if flListTags {
		fmt.Println("Tags of rules loaded:")
		tags := e.Tags()
		sort.Strings(tags)
		for _, t := range tags {
			fmt.Printf("\t%s\n", t)
		}
		os.Exit(exitSuccess)
	}

	// Scanning the files
	var events chan *evtx.GoEvtxMap
	wg := sync.WaitGroup{}

	if flJSONFormat {
		events = jsonEventGenerator()
	} else {
		events = evtxEventGenerator()
	}

	for i := 0; i < jobs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for evt := range events {
				ge := engine.GenericEvent(*evt)
				matchEvent(e, ge)
			}
		}()
	}
	// Waiting all the jobs to finish
	wg.Wait()

	log.Infof("Count Rules Used (loaded + generated): %d", e.Count())
	log.Infof("Event Scanned: %d", e.Stats.Scanned)
	log.Infof("Positives: %d", e.Stats.Detections)

	// if we were in test mode
	if flTest {
		if e.Count() == 0 {
			log.Error("Test: UNSUCCESSFUL")
			log.Infof("No rule loaded")
			os.Exit(exitFail)
		}
		if e.Stats.Scanned == 0 {
			log.Error("Test: UNSUCCESSFUL")
			log.Infof("No event scanned")
			os.Exit(exitFail)
		}
		if e.Stats.Scanned != e.Stats.Detections {
			log.Error("Test: UNSUCCESSFUL")
			log.Infof("Some events did not match any rule, events not passing the test have been printed")
			os.Exit(exitFail)
		} else {
			log.Infof("Test: SUCCESSFULL")
		}
	}

}
