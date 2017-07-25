package globals

const (
	CriticalityBound = 10
)

//Bound bound integer
func Bound(i int) int {
	if i >= CriticalityBound {
		return CriticalityBound
	}
	return i
}
