package engine

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/0xrawsec/toast"
)

func toJson(i interface{}) string {
	var b []byte
	var err error

	if b, err = json.Marshal(i); err != nil {
		panic(err)
	}

	return string(b)
}

func TestVersion(t *testing.T) {
	tt := toast.FromT(t)

	zero := ParseVersion("0.0.0")
	v := ParseVersion("2.0.0")

	tt.Assert(zero.IsZero())

	for major := 2; major < 10; major++ {
		for minor := 0; minor < 20; minor++ {
			for patch := 0; patch < 20; patch++ {
				testV := ParseVersion(fmt.Sprintf("%d.%d.%d", major, minor, patch))
				if major == 2 && minor == 0 && patch == 0 {
					tt.Assert(testV.Equals(v))
					continue
				}
				tt.Assert(testV.Above(zero))
				tt.Assert(testV.Above(v))
				tt.Assert(v.Below(testV))
				tt.Assert(toJson(testV) == fmt.Sprintf(`"%s"`, testV))
			}
		}
	}
}
