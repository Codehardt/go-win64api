package shared

type NetworkShare struct {
	Name        string
	Type        string
	Comment     string
	Permissions uint32
	MaxUses     uint32
	CurrentUses uint32
	Path        string
}
