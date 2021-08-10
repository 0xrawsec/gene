package engine

import (
	"github.com/0xrawsec/golang-utils/datastructs"
)

type Detection struct {
	Signature   *datastructs.Set
	Criticality int
	ATTACK      []Attack         `json:",omitempty"`
	Actions     *datastructs.Set `json:",omitempty"`
	attackIds   *datastructs.Set
	filtered    bool
}

func NewDetection(attack, action bool) *Detection {
	var att []Attack

	var act, attIds *datastructs.Set

	if attack {
		att = make([]Attack, 0)
		attIds = datastructs.NewSet()
	}

	if action {
		act = datastructs.NewSet()
	}

	return &Detection{
		Signature: datastructs.NewSet(),
		ATTACK:    att,
		Actions:   act,
		attackIds: attIds,
	}
}

func (d *Detection) Update(r *CompiledRule) {

	if r.Filter {
		d.filtered = true
		return
	}

	// updating criticality information
	if r.Criticality+d.Criticality > 10 {
		d.Criticality = 10
	} else {
		d.Criticality += r.Criticality
	}

	// updating attack information
	if d.ATTACK != nil {
		for _, a := range r.Attack {
			// if attack id is not already there
			if !d.attackIds.Contains(a.ID) {
				d.ATTACK = append(d.ATTACK, a)
				d.attackIds.Add(a.ID)
			}
		}
	}

	// updating actions
	if d.Actions != nil {
		d.Actions.Add(datastructs.ToInterfaceSlice(r.Actions)...)
	}

	// signature information
	d.Signature.Add(r.Name)
}

func (d *Detection) OnlyMatchedFilters() bool {
	return d.filtered && d.Signature.Len() == 0
}

func (d *Detection) AlsoMatchedFilter() bool {
	return d.filtered
}

func (d *Detection) Names() []string {
	n := make([]string, d.Signature.Len())
	for i, in := range d.Signature.List() {
		n[i] = in.(string)
	}
	return n
}

func (d *Detection) IsAlert() bool {
	return d.Signature.Len() > 0
}

func (d *Detection) Count() int {
	return d.Signature.Len()
}
