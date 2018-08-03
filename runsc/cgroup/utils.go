// +build linux

package cgroup

import (
	"fmt"
	"strings"
	"strconv"
	"errors"
	"path/filepath"
	"io/ioutil"
	"regexp"
	"os"
	"bufio"
	"time"
	"io"
	"gvisor.googlesource.com/gvisor/pkg/log"
)

var (
	ErrNotValidFormat = errors.New("line is not a valid key value format")
)

type NotFoundError struct {
	Subsystem string
}

func (e *NotFoundError) Error() string {
	return fmt.Sprintf("mountpoint for %s not found", e.Subsystem)
}

func NewNotFoundError(sub string) error {
	return &NotFoundError{
		Subsystem: sub,
	}
}

func IsNotFound(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*NotFoundError)
	return ok
}

// Saturates negative values at zero and returns a uint64.
// Due to kernel bugs, some of the memory cgroup stats can be negative.
func parseUint(s string, base, bitSize int) (uint64, error) {
	value, err := strconv.ParseUint(s, base, bitSize)
	if err != nil {
		intValue, intErr := strconv.ParseInt(s, base, bitSize)
		// 1. Handle negative values greater than MinInt64 (and)
		// 2. Handle negative values lesser than MinInt64
		if intErr == nil && intValue < 0 {
			return 0, nil
		} else if intErr != nil && intErr.(*strconv.NumError).Err == strconv.ErrRange && intValue < 0 {
			return 0, nil
		}

		return value, err
	}

	return value, nil
}

func GetClosestMountpointAncestor(dir, mountinfo string) string {
	deepestMountPoint := ""
	for _, mountInfoEntry := range strings.Split(mountinfo, "\n") {
		mountInfoParts := strings.Fields(mountInfoEntry)
		if len(mountInfoParts) < 5 {
			continue
		}
		mountPoint := mountInfoParts[4]
		if strings.HasPrefix(mountPoint, deepestMountPoint) && strings.HasPrefix(dir, mountPoint) {
			deepestMountPoint = mountPoint
		}
	}
	return deepestMountPoint
}

// Gets a string value from the specified cgroup file
func getCgroupParamString(cgroupPath, cgroupFile string) (string, error) {
	contents, err := ioutil.ReadFile(filepath.Join(cgroupPath, cgroupFile))
	if err != nil {
		return "", err
	}

	return strings.TrimSpace(string(contents)), nil
}

// Gets a single uint64 value from the specified cgroup file.
func getCgroupParamUint(cgroupPath, cgroupFile string) (uint64, error) {
	fileName := filepath.Join(cgroupPath, cgroupFile)
	contents, err := ioutil.ReadFile(fileName)
	if err != nil {
		return 0, err
	}

	res, err := parseUint(strings.TrimSpace(string(contents)), 10, 64)
	if err != nil {
		return res, fmt.Errorf("unable to parse %q as a uint from Cgroup file %q", string(contents), fileName)
	}
	return res, nil
}

// Parses a cgroup param and returns as name, value
//  i.e. "io_service_bytes 1234" will return as io_service_bytes, 1234
func getCgroupParamKeyValue(t string) (string, uint64, error) {
	parts := strings.Fields(t)
	switch len(parts) {
	case 2:
		value, err := parseUint(parts[1], 10, 64)
		if err != nil {
			return "", 0, fmt.Errorf("unable to convert param value (%q) to uint64: %v", parts[1], err)
		}

		return parts[0], value, nil
	default:
		return "", 0, ErrNotValidFormat
	}
}

func GetHugePageSize() ([]string, error) {
	var pageSizes []string
	sizeList := []string{"B", "kB", "MB", "GB", "TB", "PB"}
	files, err := ioutil.ReadDir("/sys/kernel/mm/hugepages")
	if err != nil {
		return pageSizes, err
	}
	for _, st := range files {
		nameArray := strings.Split(st.Name(), "-")
		pageSize, err := RAMInBytes(nameArray[1])
		if err != nil {
			return []string{}, err
		}
		sizeString := CustomSize("%g%s", float64(pageSize), 1024.0, sizeList)
		pageSizes = append(pageSizes, sizeString)
	}

	return pageSizes, nil
}

func writeFile(dir, file, data string) error {
	// Normally dir should not be empty, one case is that cgroup subsystem
	// is not mounted, we will get empty dir, and we want it fail here.
	if dir == "" {
		return fmt.Errorf("no such directory for %s", file)
	}
	if err := ioutil.WriteFile(filepath.Join(dir, file), []byte(data), 0700); err != nil {
		return fmt.Errorf("failed to write %v to %v: %v", data, file, err)
	}
	return nil
}

func readFile(dir, file string) (string, error) {
	data, err := ioutil.ReadFile(filepath.Join(dir, file))
	return string(data), err
}

func removePath(p string, err error) error {
	if err != nil {
		return err
	}
	if p != "" {
		return os.RemoveAll(p)
	}
	return nil
}

// ParseCgroupFile parses the given cgroup file, typically from
// /proc/<pid>/cgroup, into a map of subgroups to cgroup names.
func ParseCgroupFile(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return parseCgroupFromReader(f)
}

// helper function for ParseCgroupFile to make testing easier
func parseCgroupFromReader(r io.Reader) (map[string]string, error) {
	s := bufio.NewScanner(r)
	cgroups := make(map[string]string)

	for s.Scan() {
		text := s.Text()
		// from cgroups(7):
		// /proc/[pid]/cgroup
		// ...
		// For each cgroup hierarchy ... there is one entry
		// containing three colon-separated fields of the form:
		//     hierarchy-ID:subsystem-list:cgroup-path
		parts := strings.SplitN(text, ":", 3)
		if len(parts) < 3 {
			return nil, fmt.Errorf("invalid cgroup entry: must contain at least two colons: %v", text)
		}

		for _, subs := range strings.Split(parts[1], ",") {
			cgroups[subs] = parts[2]
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}

	return cgroups, nil
}

func isSubsystemAvailable(subsystem string) bool {
	cgroups, err := ParseCgroupFile("/proc/self/cgroup")
	if err != nil {
		return false
	}
	_, avail := cgroups[subsystem]
	return avail
}

// https://www.kernel.org/doc/Documentation/cgroup-v1/cgroups.txt
func FindCgroupMountpoint(subsystem string) (string, error) {
	mnt, _, err := FindCgroupMountpointAndRoot(subsystem)
	return mnt, err
}

func FindCgroupMountpointAndRoot(subsystem string) (string, string, error) {
	// We are not using mount.GetMounts() because it's super-inefficient,
	// parsing it directly sped up x10 times because of not using Sscanf.
	// It was one of two major performance drawbacks in container start.
	if !isSubsystemAvailable(subsystem) {
		return "", "", NewNotFoundError(subsystem)
	}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		txt := scanner.Text()
		fields := strings.Split(txt, " ")
		for _, opt := range strings.Split(fields[len(fields)-1], ",") {
			if opt == subsystem {
				return fields[4], fields[3], nil
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return "", "", err
	}

	return "", "", NewNotFoundError(subsystem)
}

func getControllerPath(subsystem string, cgroups map[string]string) (string, error) {

	if p, ok := cgroups[subsystem]; ok {
		return p, nil
	}

	if p, ok := cgroups[cgroupNamePrefix+subsystem]; ok {
		return p, nil
	}

	return "", NewNotFoundError(subsystem)
}

// GetOwnCgroup returns the relative path to the cgroup docker is running in.
func GetOwnCgroup(subsystem string) (string, error) {
	cgroups, err := ParseCgroupFile("/proc/self/cgroup")
	if err != nil {
		return "", err
	}

	return getControllerPath(subsystem, cgroups)
}

func getCgroupPathHelper(subsystem, cgroup string) (string, error) {
	mnt, root, err := FindCgroupMountpointAndRoot(subsystem)
	if err != nil {
		return "", err
	}

	// This is needed for nested containers, because in /proc/self/cgroup we
	// see pathes from host, which don't exist in container.
	relCgroup, err := filepath.Rel(root, cgroup)
	if err != nil {
		return "", err
	}

	return filepath.Join(mnt, relCgroup), nil
}

func GetOwnCgroupPath(subsystem string) (string, error) {
	cgroup, err := GetOwnCgroup(subsystem)
	if err != nil {
		return "", err
	}

	return getCgroupPathHelper(subsystem, cgroup)
}

func getCgroupRoot() (string, error) {
	cgroupRootLock.Lock()
	defer cgroupRootLock.Unlock()

	if cgroupRoot != "" {
		return cgroupRoot, nil
	}

	root, err := FindCgroupMountpointDir()
	if err != nil {
		log.Warningf("failed find cgroup mount point dir %v", err)
		return "", err
	}

	if _, err := os.Stat(root); err != nil {
		log.Warningf("failed stat cgroup root %v", err)

		return "", err
	}

	cgroupRoot = root
	return cgroupRoot, nil
}

func FindCgroupMountpointDir() (string, error) {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		text := scanner.Text()
		fields := strings.Split(text, " ")
		// Safe as mountinfo encodes mountpoints with spaces as \040.
		index := strings.Index(text, " - ")
		postSeparatorFields := strings.Fields(text[index+3:])
		numPostFields := len(postSeparatorFields)

		// This is an error as we can't detect if the mount is for "cgroup"
		if numPostFields == 0 {
			return "", fmt.Errorf("Found no fields post '-' in %q", text)
		}

		if postSeparatorFields[0] == "cgroup" {
			// Check that the mount is properly formated.
			if numPostFields < 3 {
				return "", fmt.Errorf("Error found less than 3 fields post '-' in %q", text)
			}

			return filepath.Dir(fields[4]), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}

	return "", NewNotFoundError("cgroup")
}

func PathExists(path string) bool {
	if _, err := os.Stat(path); err != nil {
		return false
	}
	return true
}

// WriteCgroupProc writes the specified pid into the cgroup's cgroup.procs file
func WriteCgroupProc(dir string, pid int) error {
	// Normally dir should not be empty, one case is that cgroup subsystem
	// is not mounted, we will get empty dir, and we want it fail here.
	if dir == "" {
		return fmt.Errorf("no such directory for %s", CgroupProcesses)
	}

	// Dont attach any pid to the cgroup if -1 is specified as a pid
	if pid != -1 {
		if err := ioutil.WriteFile(filepath.Join(dir, CgroupProcesses), []byte(strconv.Itoa(pid)), 0700); err != nil {
			return fmt.Errorf("failed to write %v to %v: %v", pid, CgroupProcesses, err)
		}
	}
	fmt.Printf("%s write cgroup proc path %s", time.Now().Format(time.RFC3339), filepath.Join(dir, CgroupProcesses))
	return nil
}

func EnterPid(cgroupPaths map[string]string, pid int) error {
	for _, path := range cgroupPaths {
		if PathExists(path) {
			if err := WriteCgroupProc(path, pid); err != nil {
				return err
			}
		}
	}
	return nil
}

// See: http://en.wikipedia.org/wiki/Binary_prefix
const (
	// Decimal

	KB = 1000
	MB = 1000 * KB
	GB = 1000 * MB
	TB = 1000 * GB
	PB = 1000 * TB

	// Binary

	KiB = 1024
	MiB = 1024 * KiB
	GiB = 1024 * MiB
	TiB = 1024 * GiB
	PiB = 1024 * TiB
)

type unitMap map[string]int64

var (
	decimalMap = unitMap{"k": KB, "m": MB, "g": GB, "t": TB, "p": PB}
	binaryMap  = unitMap{"k": KiB, "m": MiB, "g": GiB, "t": TiB, "p": PiB}
	sizeRegex  = regexp.MustCompile(`^(\d+)([kKmMgGtTpP])?[bB]?$`)
)

var decimapAbbrs = []string{"B", "kB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"}
var binaryAbbrs = []string{"B", "KiB", "MiB", "GiB", "TiB", "PiB", "EiB", "ZiB", "YiB"}

// CustomSize returns a human-readable approximation of a size
// using custom format.
func CustomSize(format string, size float64, base float64, _map []string) string {
	i := 0
	for size >= base {
		size = size / base
		i++
	}
	return fmt.Sprintf(format, size, _map[i])
}

// HumanSize returns a human-readable approximation of a size
// capped at 4 valid numbers (eg. "2.746 MB", "796 KB").
func HumanSize(size float64) string {
	return CustomSize("%.4g %s", size, 1000.0, decimapAbbrs)
}

// BytesSize returns a human-readable size in bytes, kibibytes,
// mebibytes, gibibytes, or tebibytes (eg. "44kiB", "17MiB").
func BytesSize(size float64) string {
	return CustomSize("%.4g %s", size, 1024.0, binaryAbbrs)
}

// FromHumanSize returns an integer from a human-readable specification of a
// size using SI standard (eg. "44kB", "17MB").
func FromHumanSize(size string) (int64, error) {
	return parseSize(size, decimalMap)
}

// RAMInBytes parses a human-readable string representing an amount of RAM
// in bytes, kibibytes, mebibytes, gibibytes, or tebibytes and
// returns the number of bytes, or -1 if the string is unparseable.
// Units are case-insensitive, and the 'b' suffix is optional.
func RAMInBytes(size string) (int64, error) {
	return parseSize(size, binaryMap)
}

// Parses the human-readable size string into the amount it represents.
func parseSize(sizeStr string, uMap unitMap) (int64, error) {
	matches := sizeRegex.FindStringSubmatch(sizeStr)
	if len(matches) != 3 {
		return -1, fmt.Errorf("invalid size: '%s'", sizeStr)
	}

	size, err := strconv.ParseInt(matches[1], 10, 0)
	if err != nil {
		return -1, err
	}

	unitPrefix := strings.ToLower(matches[2])
	if mul, ok := uMap[unitPrefix]; ok {
		size *= mul
	}

	return size, nil
}

// RemovePaths iterates over the provided paths removing them.
// We trying to remove all paths five times with increasing delay between tries.
// If after all there are not removed cgroups - appropriate error will be
// returned.
func RemovePaths(paths map[string]string) (err error) {
	delay := 10 * time.Millisecond
	for i := 0; i < 5; i++ {
		if i != 0 {
			time.Sleep(delay)
			delay *= 2
		}
		for s, p := range paths {
			os.RemoveAll(p)
			// TODO: here probably should be logging
			_, err := os.Stat(p)
			// We need this strange way of checking cgroups existence because
			// RemoveAll almost always returns error, even on already removed
			// cgroups
			if os.IsNotExist(err) {
				delete(paths, s)
			}
		}
		if len(paths) == 0 {
			return nil
		}
	}
	return fmt.Errorf("Failed to remove paths: %v", paths)
}

func CheckCpushares(path string, c uint64) error {
	var cpuShares uint64

	if c == 0 {
		return nil
	}

	fd, err := os.Open(filepath.Join(path, "cpu.shares"))
	if err != nil {
		return err
	}
	defer fd.Close()

	_, err = fmt.Fscanf(fd, "%d", &cpuShares)
	if err != nil && err != io.EOF {
		return err
	}

	if c > cpuShares {
		return fmt.Errorf("The maximum allowed cpu-shares is %d", cpuShares)
	} else if c < cpuShares {
		return fmt.Errorf("The minimum allowed cpu-shares is %d", cpuShares)
	}

	return nil
}
