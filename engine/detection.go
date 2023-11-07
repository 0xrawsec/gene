package engine

import (
	"encoding/json"
	"fmt"

	"github.com/0xrawsec/golang-utils/datastructs"
	"github.com/0xrawsec/jsonobj"
)

type Detection struct {
	Signature     *datastructs.Set
	Severity      int
	ATTACK        []Attack         `json:",omitempty"`
	Actions       *datastructs.Set `json:",omitempty"`
	attackIds     *datastructs.Set
	filtered      bool
	fieldNameConv NameConv
}

func (d *Detection) MarshalJSON() ([]byte, error) {
	o := jsonobj.New()

	switch d.fieldNameConv {
	case SnakeCase:
		// snake case cannot be reverted back to structure
		// if json fields name are not set to camel case
		o.Options.FieldNameConvention = jsonobj.LowerCase
	case CamelCase:
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnkNameConv, d.fieldNameConv)
	}

	o.SetField("Signature", d.Signature)
	o.SetField("Severity", d.Severity)
	if d.HasAttack() {
		o.SetField("ATTACK", o.ConvertSlice(d.ATTACK))
	}
	if d.HasActions() {
		o.SetField("Actions", d.Actions)
	}

	return json.Marshal(o)
}

func NewDetection(attack, action bool, fieldNameConv NameConv) *Detection {
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
		Signature:     datastructs.NewSet(),
		ATTACK:        att,
		Actions:       act,
		attackIds:     attIds,
		fieldNameConv: fieldNameConv,
	}
}

func (d *Detection) HasActions() bool {
	if d.Actions == nil {
		return false
	}
	return d.Actions.Len() > 0
}

func (d *Detection) HasAttack() bool {
	if d.ATTACK == nil {
		return false
	}
	return len(d.ATTACK) > 0
}

func (d *Detection) Update(r *CompiledRule) {

	if r.Filter {
		d.filtered = true
		return
	}

	// updating severity information
	if r.Severity+d.Severity > 10 {
		d.Severity = 10
	} else {
		d.Severity += r.Severity
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
	for i, in := range d.Signature.Slice() {
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
