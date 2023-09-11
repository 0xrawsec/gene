package engine

type LogType struct {
	Data      *XPath
	Channel   *XPath
	EventID   *XPath
	Hostname  *XPath
	GeneInfo  *XPath
	Timestamp *XPath
}

// Windows Event Format
var (
	systemPath = Path("/Event/System")

	TypeWinevt = LogType{
		Data:      eventDataPath,
		Channel:   systemPath.Append("Channel"),
		EventID:   systemPath.Append("EventID"),
		Hostname:  systemPath.Append("Computer"),
		GeneInfo:  Path("/Event/GeneInfo"),
		Timestamp: systemPath.Append("TimeCreated").Append("SystemTime"),
	}
)

// Kunai's log Format
var (
	TypeKunai = LogType{
		Data:      Path("/data"),
		Channel:   Path("/info/event/source"),
		EventID:   Path("/info/event/id"),
		Hostname:  Path("/info/host/hostname"),
		GeneInfo:  Path("/gene_info"),
		Timestamp: Path("/info/utc_time"),
	}
)
