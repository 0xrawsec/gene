package engine

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"sync"

	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/golang-utils/fsutil"
	"github.com/0xrawsec/golog"
)

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

	Logger = golog.FromStderr()
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
	Scanned    uint64
	Cached     uint64
	Matched    uint64
	Detections uint64
}

func (s *Stats) increment(scanned, cached, matched, detections uint64) {
	s.Scanned += scanned
	s.Cached += cached
	s.Matched += matched
	s.Detections += detections
}

// Engine defines the engine managing several rules
type Engine struct {
	sync.RWMutex
	templates *TemplateMap
	rules     []*CompiledRule
	// used to cache rules applicable per event
	rulesCache map[string][]*CompiledRule
	rawRules   map[string]string
	os         string           // OS the engine is running on
	tags       map[string][]int // will be map[tag][]int with index referencing rule in rules
	names      map[string]int   // will be map[name][]int with index referencing rule in rules
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
	// log types supported by the engine
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
	e.rulesCache = make(map[string][]*CompiledRule)
	e.rawRules = make(map[string]string)
	e.tags = make(map[string][]int)
	e.names = make(map[string]int)
	e.tagFilters = datastructs.NewSyncedSet()
	e.nameFilters = datastructs.NewSyncedSet()
	e.containers = NewContainers()
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
	e.Lock()
	defer e.Unlock()
	e.logTypes[name] = format
}

// addRule adds a rule to the current engine
func (e *Engine) addRule(r *CompiledRule) error {
	if e.os != "" && !r.matchOS(e.os) {
		Logger.Debugf("Skip rule %s because it does not match configured OS: configured=%s rule=%s", r.Name, e.os, r.OSs.Slice())
		return nil
	}

	// We skip adding the rule to the engine if we decided to match by name(s)
	if !e.nameFilters.Contains(r.Name) && e.nameFilters.Len() > 0 {
		Logger.Debugf("Skip compiling by name %s", r.Name)
		return nil
	}

	// We skip adding the rule to the engine if we decided to match by tags
	if e.tagFilters.Intersect(r.Tags).Len() == 0 && e.tagFilters.Len() > 0 {
		Logger.Debugf("Skip compiling by tags %s", r.Name)
		return nil
	}

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

func (e *Engine) loadReaderWithDec(dec Decoder) error {
	var decerr error

	for {
		var rule Rule

		decerr = dec.Decode(&rule)
		if decerr != nil {
			if !errors.Is(decerr, io.EOF) {
				return fmt.Errorf("decoding error: %w", decerr)
			}
			// We got EOF if we go there
			break
		}

		if err := e.loadRule(&rule); err != nil {
			return fmt.Errorf("failed to load rule: %w", err)
		}
	}

	return nil

}

// SetDumpRaw setter for dumpRaw flag
func (e *Engine) SetDumpRaw(value bool) {
	e.Lock()
	defer e.Unlock()
	e.dumpRaw = value
}

// SetFilters sets the filters to use in the engine
func (e *Engine) SetFilters(names, tags []string) {
	e.Lock()
	defer e.Unlock()
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
	e.Lock()
	defer e.Unlock()
	for i := low; i <= high; i++ {
		e.defaultActions[i] = actions
	}
}

// SetShowAttck sets engine flag to display ATT&CK information in matching events
// Update: member was private before, this method is kept for compatibility purposes
func (e *Engine) SetShowAttck(value bool) {
	e.Lock()
	defer e.Unlock()
	e.ShowAttack = value
}

// Count returns the number of rules successfuly loaded
func (e *Engine) Count() int {
	e.RLock()
	defer e.RUnlock()
	return len(e.rules)
}

// Tags returns the tags of the rules currently loaded into the engine
func (e *Engine) Tags() []string {
	e.RLock()
	defer e.RUnlock()
	tn := make([]string, 0, len(e.tags))
	for t := range e.tags {
		tn = append(tn, t)
	}
	return tn
}

func (e *Engine) addToContainer(container, value string) {
	e.containers.AddStringToContainer(container, value)
}

// AddToContainer adds a value to a given container and creates it if needed
// the string pushed to the container is lower cased (behaviour of
// AddSTringToContainer)
func (e *Engine) AddToContainer(container, value string) {
	e.Lock()
	defer e.Unlock()
	e.addToContainer(container, value)
}

// Blacklist insert a value (converted to lowercase) to be blacklisted
func (e *Engine) Blacklist(value string) {
	e.Lock()
	defer e.Unlock()
	e.addToContainer(blacklistContainer, value)
}

// Whitelist insert a value (converted to lowercase) to be whitelisted
func (e *Engine) Whitelist(value string) {
	e.Lock()
	defer e.Unlock()
	e.addToContainer(whitelistContainer, value)
}

// BlacklistLen returns the size of the blacklist
func (e *Engine) BlacklistLen() int {
	e.RLock()
	defer e.RUnlock()
	return e.containers.Len(blacklistContainer)
}

// WhitelistLen returns the size of the whitelist
func (e *Engine) WhitelistLen() int {
	e.RLock()
	defer e.RUnlock()
	return e.containers.Len(whitelistContainer)
}

// GetRawRule returns the raw rule according to its name
// it is convenient to get the rule after template replacement
func (e *Engine) GetRawRule(regex string) (cs chan string) {
	e.RLock()
	defer e.RUnlock()

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
	e.RLock()
	defer e.RUnlock()

	return e.rawRules[name]
}

// GetRuleNames returns a slice of containing the names of all the
// rules loaded in the engine
func (e *Engine) GetRuleNames() (names []string) {
	e.RLock()
	defer e.RUnlock()

	names = make([]string, 0, len(e.names))
	for name := range e.names {
		names = append(names, name)
	}
	return names
}

// GetCompRuleByName gets a compile rule by its name
func (e *Engine) GetCompRuleByName(name string) (r *CompiledRule) {
	e.RLock()
	defer e.RUnlock()

	if idx, ok := e.names[name]; ok {
		return e.rules[idx]
	}
	return
}

func (e *Engine) loadTemplate(templatefile string) error {
	f, err := os.Open(templatefile)
	if err != nil {
		return err
	}
	return e.templates.LoadReader(f)
}

// LoadTemplate loads a template from a file
func (e *Engine) LoadTemplate(templatefile string) error {
	e.Lock()
	defer e.Unlock()

	return e.loadTemplate(templatefile)
}

// LoadContainer loads every line found in reader into the container
func (e *Engine) LoadContainer(container string, reader io.Reader) error {
	e.Lock()
	defer e.Unlock()

	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		e.addToContainer(container, scanner.Text())
	}

	return scanner.Err()
}

// LoadReader loads rule from a ReadSeeker
func (e *Engine) LoadReader(r io.ReadSeeker) error {
	e.Lock()
	defer e.Unlock()

	return e.loadReaderWithDec(yamlRuleDecoder(r))
}

// LoadDirectory loads all the templates and rules inside a directory
// this function does not walk directory recursively
func (e *Engine) LoadDirectory(rulesDir string) error {
	e.Lock()
	defer e.Unlock()

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
		entries, err := os.ReadDir(templateDir)
		if err != nil {
			return err
		}

		// we only check for entries in rule's directory we don't recurse
		for _, de := range entries {
			ext := filepath.Ext(de.Name())
			templateFile := filepath.Join(templateDir, de.Name())
			if e.tplExtensions.Contains(ext) {
				Logger.Debugf("Loading regexp templates from file: %s", templateFile)
				err := e.loadTemplate(templateFile)
				if err != nil {
					return fmt.Errorf("error loading template (file=%s): %w", templateFile, err)
				}
			}
		}
	}

	// We can now load the rules
	// Handle both rules argument as file or directory
	switch {
	case fsutil.IsFile(realPath):
		err := e.loadFile(realPath)
		if err != nil {
			return fmt.Errorf("failed to load rule (file=%s): %w", realPath, err)
		}

	case fsutil.IsDir(realPath):
		entries, err := os.ReadDir(realPath)
		if err != nil {
			return fmt.Errorf("failed to read rule dir: %w", err)
		}

		for _, de := range entries {
			ext := filepath.Ext(de.Name())
			rulefile := filepath.Join(realPath, de.Name())
			// Check if the file extension is in the list of valid rule extension
			if e.ruleExtensions.Contains(ext) {
				err := e.loadFile(rulefile)
				if err != nil {
					return fmt.Errorf("failed to load rule (file=%s): %w", rulefile, err)
				}
			}
		}
	}
	return nil
}

func (e *Engine) loadFile(rf string) error {
	f, err := os.Open(rf)
	if err != nil {
		return err
	}
	err = e.loadReaderWithDec(yamlRuleDecoder(f))
	if err != nil {
		return fmt.Errorf("failed to load rule file \"%s\": %s", rf, err)
	}

	return nil
}

// LoadFile loads a rule file into the current engine
func (e *Engine) LoadFile(rf string) error {
	e.Lock()
	defer e.Unlock()
	return e.loadFile(rf)
}

func (e *Engine) loadRule(rule *Rule) error {
	// Check if the rule is disabled
	if rule.IsDisabled() {
		Logger.Infof("Rule \"%s\" has been disabled", rule.Name)
		return nil
	}

	//We replace the regexp templates in the rule
	rule.ReplaceTemplate(e.templates)

	// We store the rule in raw rules
	if e.dumpRaw {
		if json, err := rule.Yaml(); err != nil {
			return fmt.Errorf("cannot save raw rule: %w", err)
		} else {
			e.rawRules[rule.Name] = json
		}
	}

	// We compile the rule
	er, err := rule.Compile(e)
	if err != nil {
		return fmt.Errorf("failed to compile rule name=%s: %w", rule.Name, err)
	}

	// We add the rule to the engine
	if err := e.addRule(er); err != nil {
		return err
	}

	return nil
}

func (e *Engine) LoadRule(rule *Rule) error {
	e.Lock()
	defer e.Unlock()
	return e.loadRule(rule)
}

func (e *Engine) loadJsonBytes(data []byte) error {
	r := newSeekBuffer(data)
	return e.loadReaderWithDec(jsonRuleDecoder(r))
}

// LoadJsonBytes loads rules from []byte data
func (e *Engine) LoadJsonBytes(data []byte) error {
	e.Lock()
	defer e.Unlock()
	return e.loadJsonBytes(data)
}

// LoadJsonString loads rules from string data
func (e *Engine) LoadJsonString(data string) error {
	e.Lock()
	defer e.Unlock()
	return e.loadJsonBytes([]byte(data))
}

func (e *Engine) loadYamlBytes(data []byte) error {
	r := newSeekBuffer(data)
	return e.loadReaderWithDec(yamlRuleDecoder(r))
}

// LoadYamlString loads rules from string data
func (e *Engine) LoadYamlBytes(data []byte) error {
	e.Lock()
	defer e.Unlock()
	return e.loadYamlBytes(data)
}

// LoadYamlString loads rules from string data
func (e *Engine) LoadYamlString(data string) error {
	e.Lock()
	defer e.Unlock()
	return e.loadYamlBytes([]byte(data))
}

// get rules applicable for a given event
func (e *Engine) getRulesForEvent(evt Event) []*CompiledRule {
	// key by event id and source is good enough
	key := fmt.Sprintf("%s-%d", evt.Source(), evt.EventID())
	if _, ok := e.rulesCache[key]; !ok {
		tmp := make([]*CompiledRule, 0)
		for _, r := range e.rules {
			if r.matchStep1(evt) {
				tmp = append(tmp, r)
			}
		}
		e.rulesCache[key] = tmp
	}
	return e.rulesCache[key]
}

// Match checks if there is a match in any rule of the engine
func (e *Engine) Match(evt Event) *MatchResult {
	// initialized variables
	mr := NewMatchResult(e.ShowAttack, e.ShowActions, evt.Type().FieldNameConv)

	evtToMatch := evt
	var cache, match, det uint64

	// get rules we are sure to match against this event
	e.Lock()
	rules := e.getRulesForEvent(evt)
	e.Unlock()

	// some more optimization skipping useless instructions if no rules to match (gain a few MB/s)
	if len(rules) > 0 {
		// creating a cached event has an overhead so wo don't do it for all
		// events. Only those matching more than a couples of rules
		if len(rules) > 5 {
			evtToMatch = newCacheEvent(evt)
			cache++
		}
		// actually matching the rules
		for _, r := range rules {
			if r.matchStep2(evtToMatch) {
				mr.Update(r)
				match++
			}
		}
	}

	// Update engine's statistics
	if mr.IsDetection() {
		det++
	}

	e.Lock()
	e.Stats.increment(1, cache, match, det)
	e.Unlock()

	if mr.IsOnlyFiltered() || mr.IsEmpty() {
		// we keep original event unmodified
		return mr
	}

	// Set default actions if present
	if actions, ok := e.defaultActions[mr.Severity]; ok {
		mr.Actions.Add(datastructs.ToInterfaceSlice(actions)...)
	}

	return mr
}
