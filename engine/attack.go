package engine

// Attack structure definiton to encode information from ATT&CK Mitre
type Attack struct {
	ID          string
	Tactic      string
	Description string `json:",omitempty"`
	Reference   string
}
