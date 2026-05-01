package buildinfo

import (
	"fmt"
	"runtime"
)

var (
	version   = "unknown"
	commit    = "unknown"
	buildTime = "unknown"
)

type Info struct {
	Version   string
	Commit    string
	BuildTime string
	GoVersion string
}

func Get() Info {
	return Info{
		Version:   version,
		Commit:    commit,
		BuildTime: buildTime,
		GoVersion: runtime.Version(),
	}
}

func (i Info) String() string {
	return fmt.Sprintf("cute-pcap-mcp version=%s commit=%s build_time=%s go=%s", i.Version, i.Commit, i.BuildTime, i.GoVersion)
}
