package engine

import (
	"encoding/json"
	"fmt"
)

type Version struct {
	Major int
	Minor int
	Patch int
}

func ParseVersion(s string) (v Version) {
	fmt.Sscanf(s, "%d.%d.%d", &v.Major, &v.Minor, &v.Patch)
	return
}

func (v Version) String() string {
	return fmt.Sprintf("%d.%d.%d", v.Major, v.Minor, v.Patch)
}

func (v Version) Below(other Version) bool {
	if v.Major < other.Major {
		return true
	}
	if v.Major == other.Major {
		if v.Minor < other.Minor {
			return true
		}
		if v.Minor == other.Minor {
			return v.Patch < other.Patch
		}
	}
	return false
}

func (v Version) Above(other Version) bool {
	if v.Major > other.Major {
		return true
	}
	if v.Major == other.Major {
		if v.Minor > other.Minor {
			return true
		}
		if v.Minor == other.Minor {
			return v.Patch > other.Patch
		}
	}
	return false
}

func (v Version) Equals(other Version) bool {
	return v.Major == other.Major && v.Minor == other.Minor && v.Patch == other.Patch
}

func (v Version) IsZero() bool {
	return v.Major == 0 && v.Minor == 0 && v.Patch == 0
}

func (v *Version) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.String())
}

func (v *Version) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return err
	}
	*v = ParseVersion(s)
	return nil
}
