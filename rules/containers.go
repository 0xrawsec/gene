package rules

import (
	"fmt"
	"strings"

	"github.com/0xrawsec/golang-utils/datastructs"
)

var (
	//ErrContainerAlreadyExists should be returned in case an container name is already used in Containers
	ErrContainerAlreadyExists = fmt.Errorf("Already existing container")
)

// ContainerDB structure used to store several containers
type ContainerDB map[string]*datastructs.SyncedSet

// NewContainers initializes a new Containers structure
func NewContainers() *ContainerDB {
	c := make(ContainerDB)
	return &c
}

// AddNewContainer adds an empty container to the DB
func (c *ContainerDB) AddNewContainer(name string) error {
	container := datastructs.NewSyncedSet()
	return c.AddContainer(name, &container)
}

// AddContainer adds a new container to c
func (c *ContainerDB) AddContainer(name string, container *datastructs.SyncedSet) error {
	if _, ok := (*c)[name]; !ok {
		(*c)[name] = container
		return nil
	}
	return ErrContainerAlreadyExists
}

// AddToContainer adds a new value into a container and creates a
// new container if it does not exist yet
func (c *ContainerDB) AddToContainer(name string, values ...interface{}) {
	if !c.Has(name) {
		c.AddNewContainer(name)
	}
	container, _ := c.Get(name)
	container.Add(values...)
}

// AddStringToContainer adds new strings (converted to lower case)
// into a container and creates a new container if it does not exist yet.
func (c *ContainerDB) AddStringToContainer(name string, values ...string) {
	if !c.Has(name) {
		c.AddNewContainer(name)
	}
	container, _ := c.Get(name)
	for _, s := range values {
		container.Add(strings.ToLower(s))
	}
}

// Len gives the size of a Container
func (c *ContainerDB) Len(name string) int {
	if c.Has(name) {
		return (*c)[name].Len()
	}
	return 0
}

// Has checks if a named container is in the DB
func (c *ContainerDB) Has(name string) bool {
	_, ok := (*c)[name]
	return ok
}

//Get get a container by its name
func (c *ContainerDB) Get(name string) (*datastructs.SyncedSet, bool) {
	cont, ok := (*c)[name]
	return cont, ok
}

// Contains checks if named container contains value
func (c *ContainerDB) Contains(name string, value string) bool {
	if cont, ok := (*c)[name]; ok {
		return cont.Contains(value)
	}
	return false
}

// ContainsString checks if named container contains value ignoring value case
func (c *ContainerDB) ContainsString(name string, value string) bool {
	if cont, ok := (*c)[name]; ok {
		return cont.Contains(strings.ToLower(value))
	}
	return false
}

func (c *ContainerDB) String() string {
	out := make([]string, 0)
	for name := range *c {
		out = append(out, fmt.Sprintf("Container: %s", name))
		for _, v := range (*c)[name].List() {
			out = append(out, fmt.Sprintf("\tType:%T Value:%[1]v", v))
		}
	}
	return strings.Join(out, "\n")
}
