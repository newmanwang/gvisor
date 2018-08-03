// +build linux

package cgroup

import (
	"os"
	"path/filepath"
	"fmt"
	"sync"
	"github.com/opencontainers/runtime-spec/specs-go"
	"gvisor.googlesource.com/gvisor/pkg/log"
)

var (
	subsystems = subsystemSet{
		&CpusetGroup{},
		&DevicesGroup{},
		&MemoryGroup{},
		&CpuGroup{},
		//&CpuacctGroup{},
		&PidsGroup{},
		&HugetlbGroup{},
		&NetClsGroup{},
	}
	HugePageSizes, _ = GetHugePageSize()
)

type subsystemSet []subsystem

type subsystem interface {
	// Name returns the name of the subsystem.
	Name() string
	// Returns the stats, as 'stats', corresponding to the cgroup under 'path'.
	GetStats(path string, stats *Stats) error
	// Removes the cgroup represented by 'cgroupData'.
	Remove(*cgroupData) error
	// Creates and joins the cgroup represented by 'cgroupData'.
	Apply(*cgroupData) error
	// Set the cgroup represented by cgroup.
	Set(path string, cgroup *Cgroup) error
}

type cgroupData struct {
	root      string
	innerPath string
	config    *Cgroup
	pid       int
}

const (
	cgroupNamePrefix = "name="
	CgroupProcesses  = "cgroup.procs"
)

func (raw *cgroupData) path(subsystem string) (string, error) {
	mnt, err := FindCgroupMountpoint(subsystem)
	// If we didn't mount the subsystem, there is no point we make the path.
	if err != nil {
		return "", err
	}

	// If the cgroup name/path is absolute do not look relative to the cgroup of the init process.
	if filepath.IsAbs(raw.innerPath) {
		// Sometimes subsystems can be mounted together as 'cpu,cpuacct'.
		return filepath.Join(raw.root, filepath.Base(mnt), raw.innerPath), nil
	}

	// Use GetOwnCgroupPath instead of GetInitCgroupPath, because the creating
	// process could in container and shared pid namespace with host, and
	// /proc/1/cgroup could point to whole other world of cgroups.
	parentPath, err := GetOwnCgroupPath(subsystem)
	if err != nil {
		return "", err
	}

	return filepath.Join(parentPath, raw.innerPath), nil
}

func (raw *cgroupData) join(subsystem string) (string, error) {
	path, err := raw.path(subsystem)
	log.Debugf("Cgroup raw path %s to join", path)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(path, 0755); err != nil {
		return "", err
	}
	if err := WriteCgroupProc(path, raw.pid); err != nil {
		return "", err
	}
	return path, nil
}

type Device struct {
	// Device type, block, char, etc.
	Type rune `json:"type"`

	// Path to the device.
	Path string `json:"path"`

	// Major is the device's major number.
	Major int64 `json:"major"`

	// Minor is the device's minor number.
	Minor int64 `json:"minor"`

	// Cgroup permissions format, rwm.
	Permissions string `json:"permissions"`

	// FileMode permission bits for the device.
	FileMode os.FileMode `json:"file_mode"`

	// Uid of the device.
	Uid uint32 `json:"uid"`

	// Gid of the device.
	Gid uint32 `json:"gid"`

	// Write the file to the allowed list
	Allow bool `json:"allow"`
}

func (d *Device) CgroupString() string {
	return fmt.Sprintf("%c %s:%s %s", d.Type, deviceNumberString(d.Major), deviceNumberString(d.Minor), d.Permissions)
}

func (d *Device) Mkdev() int {
	return int((d.Major << 8) | (d.Minor & 0xff) | ((d.Minor & 0xfff00) << 12))
}

const (
	Wildcard = -1
)

// deviceNumberString converts the device number to a string return result.
func deviceNumberString(number int64) string {
	if number == Wildcard {
		return "*"
	}
	return fmt.Sprint(number)
}


type HugepageLimit struct {
	// which type of hugepage to limit.
	Pagesize string `json:"page_size"`

	// usage limit for hugepage.
	Limit uint64 `json:"limit"`
}

type Cgroup struct {
	// Path specifies the path to cgroups that are created and/or joined by the container.
	// The path is assumed to be relative to the host system cgroup mountpoint.
	Path string `json:"path"`

	// ScopePrefix describes prefix for the scope name
	ScopePrefix string `json:"scope_prefix"`

	// Paths represent the absolute cgroups paths to join.
	// This takes precedence over Path.
	Paths map[string]string

	// Resources contains various cgroups settings to apply
	*Resources
}

type Resources struct {
	Devices []*Device `json:"devices"`

	// Memory limit (in bytes)
	Memory int64 `json:"memory"`

	// Memory reservation or soft_limit (in bytes)
	MemoryReservation int64 `json:"memory_reservation"`

	// Total memory usage (memory + swap); set `-1` to enable unlimited swap
	MemorySwap int64 `json:"memory_swap"`

	// Kernel memory limit (in bytes)
	KernelMemory int64 `json:"kernel_memory"`

	// Kernel memory limit for TCP use (in bytes)
	KernelMemoryTCP int64 `json:"kernel_memory_tcp"`

	// CPU shares (relative weight vs. other containers)
	CpuShares uint64 `json:"cpu_shares"`

	// CPU hardcap limit (in usecs). Allowed cpu time in a given period.
	CpuQuota int64 `json:"cpu_quota"`

	// CPU period to be used for hardcapping (in usecs). 0 to use system default.
	CpuPeriod uint64 `json:"cpu_period"`

	// How many time CPU will use in realtime scheduling (in usecs).
	CpuRtRuntime int64 `json:"cpu_rt_quota"`

	// CPU period to be used for realtime scheduling (in usecs).
	CpuRtPeriod uint64 `json:"cpu_rt_period"`

	// CPU to use
	CpusetCpus string `json:"cpuset_cpus"`

	// MEM to use
	CpusetMems string `json:"cpuset_mems"`

	// Process limit; set <= `0' to disable limit.
	PidsLimit int64 `json:"pids_limit"`

	// Hugetlb limit (in bytes)
	HugetlbLimit []*HugepageLimit `json:"hugetlb_limit"`

	// Whether to disable OOM Killer
	OomKillDisable bool `json:"oom_kill_disable"`

	// Tuning swappiness behaviour per cgroup
	MemorySwappiness *uint64 `json:"memory_swappiness"`

	// Set class identifier for container's network packets
	NetClsClassid uint32 `json:"net_cls_classid_u"`
}

func CleanPath(path string) string {
	// Deal with empty strings nicely.
	if path == "" {
		return ""
	}

	// Ensure that all paths are cleaned (especially problematic ones like
	// "/../../../../../" which can cause lots of issues).
	path = filepath.Clean(path)

	// If the path isn't absolute, we need to do more processing to fix paths
	// such as "../../../../<etc>/some/path". We also shouldn't convert absolute
	// paths to relative ones.
	if !filepath.IsAbs(path) {
		path = filepath.Clean(string(os.PathSeparator) + path)
		// This can't fail, as (by definition) all paths are relative to root.
		path, _ = filepath.Rel(string(os.PathSeparator), path)
	}

	// Clean the path again for good measure.
	return filepath.Clean(path)
}

func stringToCgroupDeviceRune(s string) (rune, error) {
	switch s {
	case "a":
		return 'a', nil
	case "b":
		return 'b', nil
	case "c":
		return 'c', nil
	default:
		return 0, fmt.Errorf("invalid cgroup device type %q", s)
	}
}

func CreateCgroupConfig(spec *specs.Spec) (*Cgroup, error) {
	var (
		myCgroupPath string
	)

	c := &Cgroup{
		Resources: &Resources{},
	}

	if spec.Linux != nil && spec.Linux.CgroupsPath != "" {
		myCgroupPath = CleanPath(spec.Linux.CgroupsPath)
	}

	c.Path = myCgroupPath

	log.Debugf("Create cgroup config, cgroup path: %s", c.Path)

	if spec.Linux != nil {
		r := spec.Linux.Resources
		if r == nil {
			return c, nil
		}
		for i, d := range spec.Linux.Resources.Devices {
			var (
				t     = "a"
				major = int64(-1)
				minor = int64(-1)
			)
			if d.Type != "" {
				t = d.Type
			}
			if d.Major != nil {
				major = *d.Major
			}
			if d.Minor != nil {
				minor = *d.Minor
			}
			if d.Access == "" {
				return nil, fmt.Errorf("device access at %d field cannot be empty", i)
			}
			dt, err := stringToCgroupDeviceRune(t)
			if err != nil {
				return nil, err
			}
			dd := &Device{
				Type:        dt,
				Major:       major,
				Minor:       minor,
				Permissions: d.Access,
				Allow:       d.Allow,
			}
			c.Resources.Devices = append(c.Resources.Devices, dd)
		}
		if r.Memory != nil {
			if r.Memory.Limit != nil {
				c.Resources.Memory = *r.Memory.Limit
			}
			if r.Memory.Reservation != nil {
				c.Resources.MemoryReservation = *r.Memory.Reservation
			}
			if r.Memory.Swap != nil {
				c.Resources.MemorySwap = *r.Memory.Swap
			}
			if r.Memory.Kernel != nil {
				c.Resources.KernelMemory = *r.Memory.Kernel
			}
			if r.Memory.KernelTCP != nil {
				c.Resources.KernelMemoryTCP = *r.Memory.KernelTCP
			}
			if r.Memory.Swappiness != nil {
				c.Resources.MemorySwappiness = r.Memory.Swappiness
			}
			if r.Memory.DisableOOMKiller != nil {
				c.Resources.OomKillDisable = *r.Memory.DisableOOMKiller
			}
		}
		if r.CPU != nil {
			if r.CPU.Shares != nil {
				c.Resources.CpuShares = *r.CPU.Shares
			}
			if r.CPU.Quota != nil {
				c.Resources.CpuQuota = *r.CPU.Quota
			}
			if r.CPU.Period != nil {
				c.Resources.CpuPeriod = *r.CPU.Period
			}
			if r.CPU.RealtimeRuntime != nil {
				c.Resources.CpuRtRuntime = *r.CPU.RealtimeRuntime
			}
			if r.CPU.RealtimePeriod != nil {
				c.Resources.CpuRtPeriod = *r.CPU.RealtimePeriod
			}
			if r.CPU.Cpus != "" {
				c.Resources.CpusetCpus = r.CPU.Cpus
			}
			if r.CPU.Mems != "" {
				c.Resources.CpusetMems = r.CPU.Mems
			}
		}
		if r.Pids != nil {
			c.Resources.PidsLimit = r.Pids.Limit
		}
		for _, l := range r.HugepageLimits {
			c.Resources.HugetlbLimit = append(c.Resources.HugetlbLimit, &HugepageLimit{
				Pagesize: l.Pagesize,
				Limit:    l.Limit,
			})
		}
		if r.Network != nil {
			if r.Network.ClassID != nil {
				c.Resources.NetClsClassid = *r.Network.ClassID
			}
		}
	}
	return c, nil
}

type Manager struct {
	mu      sync.Mutex
	Cgroups *Cgroup
	Paths   map[string]string
}

// The absolute path to the root of the cgroup hierarchies.
var cgroupRootLock sync.Mutex
var cgroupRoot string


func getCgroupData(c *Cgroup, pid int) (*cgroupData, error) {
	root, err := getCgroupRoot()
	if err != nil {
		log.Warningf("failed get cgroup root, pid %d", pid)
		return nil, err
	}

	// XXX: Do not remove this code. Path safety is important! -- cyphar
	cgPath := CleanPath(c.Path)

	innerPath := cgPath

	log.Debugf("Got cgroup data: root %s, innerPath %s\n", root, innerPath)

	return &cgroupData{
		root:      root,
		innerPath: innerPath,
		config:    c,
		pid:       pid,
	}, nil
}

func NewCgroupsManager(config *Cgroup, paths map[string]string) Manager {
	return Manager{
		Cgroups: config,
		Paths:   paths,
	}
}

func (m *Manager) GetPaths() map[string]string {
	m.mu.Lock()
	paths := m.Paths
	m.mu.Unlock()
	return paths
}

func (m *Manager) Apply(pid int) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	var c = m.Cgroups

	d, err := getCgroupData(m.Cgroups, pid)
	if err != nil {
		log.Warningf("Failed to get cgroup data for pid %d", pid)
		return err
	}

	log.Debugf("Apply cgroup: pathes %v\n", c.Paths)

	m.Paths = make(map[string]string)
	if c.Paths != nil {
		for name, path := range c.Paths {
			_, err := d.path(name)
			if err != nil {
				if IsNotFound(err) {
					continue
				}
				return err
			}
			m.Paths[name] = path
		}
		return EnterPid(m.Paths, pid)
	}

	for _, sys := range subsystems {
		// TODO: Apply should, ideally, be reentrant or be broken up into a separate
		// create and join phase so that the cgroup hierarchy for a container can be
		// created then join consists of writing the process pids to cgroup.procs
		p, err := d.path(sys.Name())
		if err != nil {
			// The non-presence of the devices subsystem is
			// considered fatal for security reasons.
			if IsNotFound(err) && sys.Name() != "devices" {
				continue
			}
			return err
		}
		m.Paths[sys.Name()] = p

		if err := sys.Apply(d); err != nil {
			if os.IsPermission(err) && m.Cgroups.Path == "" {
				// If we didn't set a cgroup path, then let's defer the error here
				// until we know whether we have set limits or not.
				// If we hadn't set limits, then it's ok that we couldn't join this cgroup, because
				// it will have the same limits as its parent.
				delete(m.Paths, sys.Name())
				continue
			}
			return err
		}

	}
	return nil
}

func (m *Manager) Set() error {
	// If Paths are set, then we are just joining cgroups paths
	// and there is no need to set any values.
	if m.Cgroups.Paths != nil {
		return nil
	}

	paths := m.GetPaths()
	for _, sys := range subsystems {
		path := paths[sys.Name()]
		if err := sys.Set(path, m.Cgroups); err != nil {
			if path == "" {
				// cgroup never applied
				return fmt.Errorf("cannot set limits on the %s cgroup, as the container has not joined it", sys.Name())
			}
			return err
		}
	}

	if m.Paths["cpu"] != "" {
		if err := CheckCpushares(m.Paths["cpu"], m.Cgroups.Resources.CpuShares); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) Destroy() error {
	if m.Cgroups.Paths != nil {
		return nil
	}

	log.Debugf("Destroy cgroup: cgroup paths %v", m.Cgroups.Paths)

	m.mu.Lock()
	defer m.mu.Unlock()
	if err := RemovePaths(m.Paths); err != nil {
		return err
	}
	m.Paths = make(map[string]string)
	return nil
}