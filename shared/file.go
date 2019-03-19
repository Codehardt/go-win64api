package shared

type OpenFile struct {
	ID          uint32
	Permissions uint32
	NumLocks    uint32
	Pathname    string
	Username    string
}
