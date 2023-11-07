package engine

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golang-utils/fsutil/fswalker"
	"github.com/0xrawsec/golang-utils/log"
)

/////////////////////////// Utility functions //////////////////////////////////

func seekerGoto(reader io.ReadSeeker, offset int64, flag int) int64 {
	off, err := reader.Seek(offset, flag)
	if err != nil {
		panic(err)
	}
	return off
}

func nextRuleOffset(endLastRuleOffset int64, reader io.ReadSeeker) int64 {
	var char [1]byte
	var cnt int64
	cur := seekerGoto(reader, 0, os.SEEK_CUR)
	seekerGoto(reader, endLastRuleOffset, os.SEEK_SET)
	for read, err := reader.Read(char[:]); read == 1 && err == nil; read, err = reader.Read(char[:]) {
		if char[0] == '{' {
			break
		}
		cnt++
	}
	seekerGoto(reader, cur, os.SEEK_SET)
	return endLastRuleOffset + cnt
}

func findLineError(ruleOffset int64, reader io.ReadSeeker) (int64, int64) {
	var line, offset int64
	var buf [4096]byte

	// Go back to beginning of reader
	seekerGoto(reader, 0, os.SEEK_SET)

ReadLoop:
	for read, err := reader.Read(buf[:]); read > 0 && err == nil; read, err = reader.Read(buf[:]) {
		for _, c := range buf[:read] {
			if offset == ruleOffset {
				break ReadLoop
			}
			if c == '\n' {
				line++
			}
			offset++
		}
	}
	// Line number always starts at 1
	line++
	return line, offset
}

////////////////////////////////// Engine /////////////////////////////////////

const (
	blacklistContainer = "blacklist"
	whitelistContainer = "whitelist"
)

var (

	// DefaultRuleExtensions default extensions for rule files
	DefaultRuleExtensions = datastructs.NewInitSyncedSet(".gen", ".gene")
	// DefaultTplExtensions default extensions for template files
	DefaultTplExtensions = datastructs.NewInitSyncedSet(".toml")
)

// ErrRuleExist definition
type ErrRuleExist struct {
	ruleName string
}

// Error error implementation
func (e ErrRuleExist) Error() string {
	return fmt.Sprintf("Rule \"%s\" already exists", e.ruleName)
}

type Stats struct {
	Scanned   uint64
	Positives uint64
}

// Engine defines the engine managing several rules
type Engine struct {
	sync.RWMutex
	templates *TemplateMap
	rules     []*CompiledRule
	rawRules  map[string]string
	os        string           // OS the engine is running on
	tags      map[string][]int // will be map[tag][]int with index referencing rule in rules
	names     map[string]int   // will be map[name][]int with index referencing rule in rules
	// Filters used to choose which rule to compile in case of match by tag/name
	tagFilters  *datastructs.SyncedSet
	nameFilters *datastructs.SyncedSet
	dumpRaw     bool
	containers  *ContainerDB
	// Control allowed file extensions
	ruleExtensions *datastructs.SyncedSet
	tplExtensions  *datastructs.SyncedSet
	// default actions
	defaultActions map[int][]string
	// log formats
	logTypes map[string]*LogType

	// engine statistics
	Stats       Stats
	ShowActions bool
	ShowAttack  bool
}

// NewEngine creates a new engine
func NewEngine() (e *Engine) {
	e = &Engine{}
	e.templates = NewTemplateMap()
	e.rules = make([]*CompiledRule, 0)
	e.rawRules = make(map[string]string)
	e.tags = make(map[string][]int)
	e.names = make(map[string]int)
	e.tagFilters = datastructs.NewSyncedSet()
	e.nameFilters = datastructs.NewSyncedSet()
	e.containers = NewContainers()
	// We do not create the containers so that they are not considered as empty
	//e.containers.AddNewContainer("blacklist")
	//e.containers.AddNewContainer("whitelist")
	e.ruleExtensions = DefaultRuleExtensions
	e.tplExtensions = DefaultTplExtensions
	e.defaultActions = make(map[int][]string)
	e.logTypes = make(map[string]*LogType)
	// we set all known logTypes
	for n, t := range logTypes {
		e.logTypes[n] = t
	}
	return
}

func (e *Engine) AddLogFormat(name string, format *LogType) {
	e.logTypes[name] = format
}

// addRule adds a rule to the current engine
func (e *Engine) addRule(r *CompiledRule) error {

	if e.os != "" && !r.matchOS(e.os) {
		log.Debugf("Skip rule %s because it does not match configured OS: configured=%s rule=%s", r.Name, e.os, r.OSs.Slice())
		return nil
	}

	// We skip adding the rule to the engine if we decided to match by name(s)
	if !e.nameFilters.Contains(r.Name) && e.nameFilters.Len() > 0 {
		log.Debugf("Skip compiling by name %s", r.Name)
		return nil
	}

	// We skip adding the rule to the engine if we decided to match by tags
	if e.tagFilters.Intersect(r.Tags).Len() == 0 && e.tagFilters.Len() > 0 {
		log.Debugf("Skip compiling by tags %s", r.Name)
		return nil
	}

	e.Lock()
	defer e.Unlock()
	// don't need to increment since element will be appended at i
	i := len(e.rules)
	if _, ok := e.names[r.Name]; ok {
		return ErrRuleExist{r.Name}
	}
	e.rules = append(e.rules, r)
	e.names[r.Name] = i

	// Update the map of tags in order to speed up search by tag
	for _, t := range r.Tags.Slice() {
		key := t.(string)
		e.tags[key] = append(e.tags[key], i)
	}

	return nil
}

func (e *Engine) loadReader(reader io.ReadSeeker) error {
	var decerr error
	dec := NewRuleDecoder(reader)

	for {
		var jRule Rule
		decoderOffset := seekerGoto(reader, 0, io.SeekCurrent)
		// We don't handle error here
		decBuffer, _ := io.ReadAll(dec.Buffered())
		ruleOffset := nextRuleOffset(decoderOffset-int64(len(decBuffer)), reader)

		decerr = dec.Decode(&jRule)
		if decerr != nil {
			if decerr != io.EOF {
				ruleLine, offInLine := findLineError(ruleOffset, reader)
				return fmt.Errorf("JSON parsing (rule line=%d offset=%d) (error=%s)", ruleLine, offInLine, decerr)
			}
			// We got EOF if we go there
			break
		}

		if err := e.LoadRule(&jRule); err != nil {
			ruleLine, offInLine := findLineError(ruleOffset, reader)
			return fmt.Errorf("failed to load rule (rule line=%d offset=%d) (error=%s)", ruleLine, offInLine, err)
		}
	}

	return nil
}

// SetDumpRaw setter for dumpRaw flag
func (e *Engine) SetDumpRaw(value bool) {
	e.dumpRaw = value
}

// SetFilters sets the filters to use in the engine
func (e *Engine) SetFilters(names, tags []string) {
	for _, n := range names {
		e.nameFilters.Add(n)
	}
	for _, t := range tags {
		e.tagFilters.Add(t)
	}
}

// SetDefaultActions sets default actions given to event reaching
// certain severity within [low; high]
func (e *Engine) SetDefaultActions(low, high int, actions []string) {
	for i := low; i <= high; i++ {
		e.defaultActions[i] = actions
	}
}

// SetShowAttck sets engine flag to display ATT&CK information in matching events
// Update: member was private before, this method is kept for compatibility purposes
func (e *Engine) SetShowAttck(value bool) {
	e.ShowAttack = value
}

// Count returns the number of rules successfuly loaded
func (e *Engine) Count() int {
	return len(e.rules)
}

// Tags returns the tags of the rules currently loaded into the engine
func (e *Engine) Tags() []string {
	tn := make([]string, 0, len(e.tags))
	for t := range e.tags {
		tn = append(tn, t)
	}
	return tn
}

// AddToContainer adds a value to a given container and creates it if needed
// the string pushed to the container is lower cased (behaviour of
// AddSTringToContainer)
func (e *Engine) AddToContainer(container, value string) {
	e.containers.AddStringToContainer(container, value)
}

// Blacklist insert a value (converted to lowercase) to be blacklisted
func (e *Engine) Blacklist(value string) {
	e.containers.AddStringToContainer(blacklistContainer, value)
}

// Whitelist insert a value (converted to lowercase) to be whitelisted
func (e *Engine) Whitelist(value string) {
	e.containers.AddStringToContainer(whitelistContainer, value)
}

// BlacklistLen returns the size of the blacklist
func (e *Engine) BlacklistLen() int {
	return e.containers.Len(blacklistContainer)
}

// WhitelistLen returns the size of the whitelist
func (e *Engine) WhitelistLen() int {
	return e.containers.Len(whitelistContainer)
}

// GetRawRule returns the raw rule according to its name
// it is convenient to get the rule after template replacement
func (e *Engine) GetRawRule(regex string) (cs chan string) {
	cs = make(chan string)
	nameRegexp := regexp.MustCompile(regex)
	go func() {
		defer close(cs)
		sorted := make([]string, 0, len(e.rawRules))
		for name := range e.rawRules {
			sorted = append(sorted, name)
		}
		sort.Strings(sorted)
		for _, name := range sorted {
			if nameRegexp.MatchString(name) {
				cs <- e.rawRules[name]
			}
		}
	}()
	return cs
}

// GetRawRuleByName returns the raw rule for a given rule name
func (e *Engine) GetRawRuleByName(name string) string {
	return e.rawRules[name]
}

// GetRuleNames returns a slice of containing the names of all the
// rules loaded in the engine
func (e *Engine) GetRuleNames() (names []string) {
	names = make([]string, 0, len(e.names))
	for name := range e.names {
		names = append(names, name)
	}
	return names
}

// GetCRuleByName gets a compile rule by its name
func (e *Engine) GetCRuleByName(name string) (r *CompiledRule) {
	if idx, ok := e.names[name]; ok {
		return e.rules[idx]
	}
	return
}

// LoadTemplate loads a template from a file
func (e *Engine) LoadTemplate(templatefile string) error {
	f, err := os.Open(templatefile)
	if err != nil {
		return err
	}
	return e.templates.LoadReader(f)
}

// LoadContainer loads every line found in reader into the container
func (e *Engine) LoadContainer(container string, reader io.Reader) error {
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		e.AddToContainer(container, scanner.Text())
	}

	return scanner.Err()
}

// LoadReader loads rule from a ReadSeeker
func (e *Engine) LoadReader(reader io.ReadSeeker) error {
	return e.loadReader(reader)
}

// LoadDirectory loads all the templates and rules inside a directory
// this function does not walk directory recursively
func (e *Engine) LoadDirectory(rulesDir string) error {
	// Loading the rules
	realPath, err := fsutil.ResolveLink(rulesDir)
	if err != nil {
		return err
	}

	// Loading the templates first, we assume templates are located under rulesDir
	templateDir := realPath
	if fsutil.IsFile(realPath) {
		templateDir = filepath.Dir(realPath)
	}

	if fsutil.IsDir(templateDir) {
		for wi := range fswalker.Walk(templateDir) {
			for _, fi := range wi.Files {
				ext := filepath.Ext(fi.Name())
				templateFile := filepath.Join(wi.Dirpath, fi.Name())
				if e.tplExtensions.Contains(ext) {
					log.Debugf("Loading regexp templates from file: %s", templateFile)
					err := e.LoadTemplate(templateFile)
					if err != nil {
						log.Errorf("Error loading %s: %s", templateFile, err)
						return err
					}
				}
			}
		}
	}

	// Handle both rules argument as file or directory
	switch {
	case fsutil.IsFile(realPath):
		err := e.LoadFile(realPath)
		if err != nil {
			log.Errorf("Error loading %s: %s", realPath, err)
			return err
		}

	case fsutil.IsDir(realPath):
		for wi := range fswalker.Walk(realPath) {
			for _, fi := range wi.Files {
				ext := filepath.Ext(fi.Name())
				rulefile := filepath.Join(wi.Dirpath, fi.Name())
				log.Debug(ext)
				// Check if the file extension is in the list of valid rule extension
				if e.ruleExtensions.Contains(ext) {
					err := e.LoadFile(rulefile)
					if err != nil {
						log.Errorf("Error loading %s: %s", rulefile, err)
						return err
					}
				}
			}
		}
	}
	return nil
}

// LoadFile loads a rule file into the current engine
func (e *Engine) LoadFile(rulefile string) error {
	f, err := os.Open(rulefile)
	if err != nil {
		return err
	}
	err = e.loadReader(f)
	if err != nil {
		return fmt.Errorf("failed to load rule file \"%s\": %s", rulefile, err)
	}
	return nil
}

func (e *Engine) LoadRule(rule *Rule) error {
	// Check if the rule is disabled
	if rule.IsDisabled() {
		log.Infof("Rule \"%s\" has been disabled", rule.Name)
		return nil
	}

	//We replace the regexp templates in the rule
	rule.ReplaceTemplate(e.templates)

	// We store the rule in raw rules
	if e.dumpRaw {
		if json, err := rule.JSON(); err != nil {
			return fmt.Errorf("cannot save raw rule: %w", err)
		} else {
			e.rawRules[rule.Name] = json
		}
	}

	// We compile the rule
	er, err := rule.Compile(e)
	if err != nil {
		return fmt.Errorf("failed to compile rule: %w", err)
	}

	// We add the rule to the engine
	if err := e.addRule(er); err != nil {
		return err
	}

	return nil
}

// LoadBytes loads rules from []byte data
func (e *Engine) LoadBytes(data []byte) error {
	return e.LoadReader(newSeekBuffer(data))
}

// LoadString loads rules from string data
func (e *Engine) LoadString(data string) error {
	return e.LoadBytes([]byte(data))
}

// MatchOrFilter checks if there is a match in any rule of the engine. The only difference with Match function is that
// it also return a flag indicating if the event is filtered.
func (e *Engine) MatchOrFilter(evt Event) (names []string, severity int, filtered bool) {

	// initialized variables
	detection := NewDetection(e.ShowAttack, e.ShowActions, evt.Type().FieldNameConv)

	e.RLock()
	for _, r := range e.rules {
		if r.Match(evt) {

			detection.Update(r)

			// Do not need to go further if it is a filter rule
			if r.Filter {
				continue
			}
		}
	}
	// Unlock so that we can update engine
	e.RUnlock()

	// Update engine's statistics
	e.Lock()
	e.Stats.Scanned++
	if detection.IsAlert() {
		e.Stats.Positives++
	}
	e.Unlock()

	if detection.OnlyMatchedFilters() {
		// we keep original event unmodified
		return nil, 0, true
	}

	// Set default actions if present
	if actions, ok := e.defaultActions[detection.Severity]; ok {
		detection.Actions.Add(datastructs.ToInterfaceSlice(actions)...)
	}

	evt.SetDetection(detection)

	return detection.Names(), detection.Severity, detection.AlsoMatchedFilter()
}
