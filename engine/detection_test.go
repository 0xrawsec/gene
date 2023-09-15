package engine

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/0xrawsec/toast"
)

func TestDetection(t *testing.T) {
	tt := toast.FromT(t)

	d := NewDetection(true, true, CamelCase)
	d.Criticality = 10

	d.Signature.Add("test")
	d.Actions.Add("do_something")
	d.ATTACK = append(d.ATTACK, Attack{
		ID:        "T4242",
		Tactic:    "Hola que tal",
		Reference: "https://some.reference",
	})

	b, err := json.Marshal(&d)
	tt.CheckErr(err)
	tt.Log(string(b))
	tt.Assert(string(b) == `{"Signature":["test"],"Criticality":10,"ATTACK":[{"ID":"T4242","Tactic":"Hola que tal","Description":"","Reference":"https://some.reference"}],"Actions":["do_something"]}`)

	d.fieldNameConv = SnakeCase
	b, err = json.Marshal(&d)
	tt.CheckErr(err)
	tt.Log(string(b))
	tt.Assert(string(b) == `{"signature":["test"],"criticality":10,"attack":[{"id":"T4242","tactic":"Hola que tal","description":"","reference":"https://some.reference"}],"actions":["do_something"]}`)

	// checking if unmarshalling works as well we fields get lowercased
	unmDet := Detection{}
	tt.CheckErr(json.Unmarshal(b, &unmDet))

	tt.Assert(unmDet.Criticality == d.Criticality)
	tt.Assert(unmDet.Signature.Equal(d.Signature))
	tt.Assert(unmDet.Actions.Equal(d.Actions))
	tt.Assert(reflect.DeepEqual(unmDet.ATTACK, d.ATTACK))
}
