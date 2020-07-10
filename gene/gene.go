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

	"github.com/0xrawsec/gene/engine"
	"github.com/0xrawsec/gene/reducer"
	"github.com/0xrawsec/gene/rules"
	"github.com/0xrawsec/golang-evtx/evtx"
	"github.com/0xrawsec/golang-utils/args"
	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/golang-utils/log"
	"github.com/0xrawsec/golang-utils/progress"
	"github.com/0xrawsec/golang-utils/readers"
)

//////////////////////////// Utilities //////////////////////////////

func matchEvent(e *engine.Engine, event *evtx.GoEvtxMap) {
	n, crit := e.Match(event)
	// We print only if we are not in test mode
	if len(n) > 0 && !test {
		// Prints out the events with timestamp or not
		if showTimestamp && crit >= criticalityThresh {
			fmt.Printf("%d: %s\n", event.TimeCreated().Unix(), string(evtx.ToJSON(event)))
		} else {
			if crit >= criticalityThresh {
				fmt.Println(string(evtx.ToJSON(event)))
			}
		}
	} else if allEvents || (test && len(n) == 0) {
		if showTimestamp {
			fmt.Printf("%d: %s\n", event.TimeCreated().Unix(), string(evtx.ToJSON(event)))
		} else {
			fmt.Println(string(evtx.ToJSON(event)))
		}
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
					log.LogError(err)
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
					log.LogError(err)
					break
				}
				// Printing Progress
				eventCnt++
				if showProgress && eventCnt >= oldEventCnt {
					delta := time.Now().Sub(start)
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
				if showProgress && eventCnt >= oldEventCnt {
					delta := time.Now().Sub(start)
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
	criticalityPath = evtx.Path("/Event/GeneInfo/Criticality")
	sigPath         = evtx.Path("/Event/GeneInfo/Signature")
	computerPath    = evtx.Path("/Event/System/Computer")
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
	debug         bool
	showTimestamp bool
	allEvents     bool
	showProgress  bool
	inJSONFmt     bool
	trace         bool
	template      bool
	verify        bool
	listTags      bool
	versionFlag   bool
	reduceFlag    bool
	showAttckFlag bool
	test          bool
	cpuprofile    string
	tags          []string
	names         []string
	tagsVar       args.ListVar
	namesVar      args.ListVar
	dumpsVar      args.ListVar

	criticalityThresh int

	whitelist string
	blacklist string

	rulesPath string
	ruleExts  = args.ListVar{".gen", ".gene"}
	jobs      = 1

	tplExt = ".tpl"
)

func main() {
	flag.BoolVar(&debug, "d", debug, "Enable debug mode")
	flag.BoolVar(&showTimestamp, "ts", showTimestamp, "Show the timestamp of the event when printing")
	flag.BoolVar(&allEvents, "all", allEvents, "Print all events (even the one not matching rules)")
	flag.BoolVar(&showProgress, "progress", showProgress, "Show progress")
	flag.BoolVar(&inJSONFmt, "j", inJSONFmt, "Input is in JSON format")
	flag.BoolVar(&trace, "trace", trace, "Tells the engine to use the trace function of the rules. Trace mode implies a number of job equal to 1")
	flag.BoolVar(&template, "template", template, "Prints a rule template")
	flag.BoolVar(&verify, "verify", verify, "Verify the rules and exit.")
	flag.BoolVar(&listTags, "lt", listTags, "List tags of rules loaded into the engine")
	flag.BoolVar(&versionFlag, "version", versionFlag, "Show version information and exit")
	flag.BoolVar(&reduceFlag, "reduce", reduceFlag, "Aggregate the results of already processed events and outputs condensed information")
	flag.BoolVar(&showAttckFlag, "a", showAttckFlag, "Show Mitre ATT&CK information in matching events")
	flag.BoolVar(&test, "test", test, "Test mode. Prints non matching events and returns a non zero status code if not all events match.")
	flag.StringVar(&rulesPath, "r", rulesPath, "Rule file or directory")
	flag.StringVar(&cpuprofile, "cpuprofile", cpuprofile, "Profile CPU")
	flag.StringVar(&whitelist, "wl", whitelist, "File containing values to insert into the whitelist")
	flag.StringVar(&blacklist, "bl", blacklist, "File containing values to insert into the blacklist")
	flag.IntVar(&criticalityThresh, "c", criticalityThresh, "Criticality treshold. Prints only if criticality above threshold")
	flag.IntVar(&jobs, "jobs", jobs, "Number of parallel jobs to run. It may result in events printed in different order than provided. If <= 0 takes all available processors")
	flag.Var(&ruleExts, "e", "Rule file extensions to load")
	flag.Var(&tagsVar, "t", "Tags to search for (comma separated)")
	flag.Var(&namesVar, "n", "Rule names to match against (comma separated)")
	flag.Var(&dumpsVar, "dump", "Dumps the rules matching the regex provided (comma separated) and then exits. Usefull to verify if regexp template is correctly applied.")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s: %[1]s -r RULES [OPTIONS] FILES...\n", filepath.Base(os.Args[0]))
		flag.PrintDefaults()
		os.Exit(0)
	}

	flag.Parse()

	if cpuprofile != "" {
		f, err := os.Create(cpuprofile)
		if err != nil {
			log.LogErrorAndExit(err)
		}
		pprof.StartCPUProfile(f)
		defer pprof.StopCPUProfile()
	}

	// Enable debugging mode if needed
	if debug {
		log.InitLogger(log.LDebug)
	}

	// If version switch
	if versionFlag {
		printInfo(os.Stderr)
		os.Exit(exitSuccess)
	}

	// Handling job parameter
	// If jobs is not in affordable range
	if jobs <= 0 || jobs > runtime.NumCPU() {
		jobs = runtime.NumCPU()

	}
	// If trace mode is enabled, it is better to process events in order
	if trace {
		jobs = 1
	}

	// Display rule template and exit if template flag
	if template {
		r := rules.NewRule()
		r.Meta.Attack = append(r.Meta.Attack, rules.Attack{})
		b, err := json.Marshal(r)
		if err != nil {
			log.LogErrorAndExit(err, exitFail)
		}
		fmt.Println(string(b))
		os.Exit(exitSuccess)
	}

	// Control parameters
	if rulesPath == "" {
		log.LogErrorAndExit(fmt.Errorf("No rule file to load"), exitFail)
	}

	// Initialization
	e := engine.NewEngine(trace)
	setRuleExts := datastructs.NewSyncedSet()
	tags = []string(tagsVar)
	names = []string(namesVar)
	// Enable rule dumping on engine side
	e.SetDumpRaw(len(dumpsVar) > 0)
	// Enable showing Mitre ATT&CK information
	e.SetShowAttck(showAttckFlag)

	// Validation
	if len(tags) > 0 && len(names) > 0 {
		log.LogErrorAndExit(fmt.Errorf("Cannot search by tags and names at the same time"), exitFail)
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
			log.LogErrorAndExit(err, exitFail)
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
			log.LogErrorAndExit(err, exitFail)
		}
		for line := range readers.Readlines(blf) {
			e.Blacklist(string(line))
		}
		blf.Close()
	}
	log.Infof("Size of blacklist container: %d", e.BlacklistLen())

	// Loading the rules and templates
	realPath, err := fsutil.ResolveLink(rulesPath)
	if err != nil {
		log.LogErrorAndExit(err, exitFail)
	}

	// Loading the templates first
	templateDir := realPath
	if fsutil.IsFile(realPath) {
		templateDir = filepath.Dir(realPath)
	}
	for wi := range fswalker.Walk(templateDir) {
		for _, fi := range wi.Files {
			ext := filepath.Ext(fi.Name())
			templateFile := filepath.Join(wi.Dirpath, fi.Name())
			if ext == tplExt {
				log.Infof("Loading regexp templates from file: %s", templateFile)
				err := e.LoadTemplate(templateFile)
				if err != nil {
					log.Errorf("Error loading %s: %s", templateFile, err)
				}
			}
		}
	}

	// Handle both rules argument as file or directory
	cntFailure := 0
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
						cntFailure++
					}
				}
			}
		}
	default:
		log.LogErrorAndExit(fmt.Errorf("Cannot resolve %s to file or dir", rulesPath), exitFail)
	}

	// Show message about successfuly compiled rules
	log.Infof("Loaded %d rules", e.Count())

	// If we just wanted to verify the rules, we should exit whatever
	// the status of the compilation
	if verify {
		if cntFailure > 0 {
			log.LogErrorAndExit(fmt.Errorf("Rule(s) compilation (%d files failed): FAILURE", cntFailure), exitFail)
		}
		log.Infof("Rule(s) compilation: SUCCESSFUL")
		os.Exit(exitSuccess)
	}

	// If we want to reduce
	if reduceFlag {
		reduce(&e)
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
	if listTags {
		fmt.Println("Tags of rules loaded:")
		tags := e.Tags()
		sort.Strings(tags)
		for _, t := range tags {
			fmt.Println(fmt.Sprintf("\t%s", t))
		}
		os.Exit(exitSuccess)
	}

	// Scanning the files
	var events chan *evtx.GoEvtxMap
	wg := sync.WaitGroup{}

	if inJSONFmt {
		events = jsonEventGenerator()
	} else {
		events = evtxEventGenerator()
	}

	for i := 0; i < jobs; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for event := range events {
				matchEvent(&e, event)
			}
		}()
	}
	// Waiting all the jobs to finish
	wg.Wait()

	log.Infof("Count Rules Used (loaded + generated): %d", e.Count())
	log.Infof("Event Scanned: %d", e.Stats.Scanned)
	log.Infof("Positives: %d", e.Stats.Positives)

	// if we were in test mode
	if test {
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
		if e.Stats.Scanned != e.Stats.Positives {
			log.Error("Test: UNSUCCESSFUL")
			log.Infof("Some events did not match any rule, events not passing the test have been printed")
			os.Exit(exitFail)
		} else {
			log.Infof("Test: SUCCESSFULL")
		}
	}

}
