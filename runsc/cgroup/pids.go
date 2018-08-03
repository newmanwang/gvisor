// +build linux

package cgroup

import (
	"fmt"
	"path/filepath"
	"strconv"

)

type PidsGroup struct {
}

func (s *PidsGroup) Name() string {
	return "pids"
}

func (s *PidsGroup) Apply(d *cgroupData) error {
	_, err := d.join("pids")
	if err != nil && !IsNotFound(err) {
		return err
	}
	return nil
}

func (s *PidsGroup) Set(path string, cgroup *Cgroup) error {
	if cgroup.Resources.PidsLimit != 0 {
		// "max" is the fallback value.
		limit := "max"

		if cgroup.Resources.PidsLimit > 0 {
			limit = strconv.FormatInt(cgroup.Resources.PidsLimit, 10)
		}

		if err := writeFile(path, "pids.max", limit); err != nil {
			return err
		}
	}

	return nil
}

func (s *PidsGroup) Remove(d *cgroupData) error {
	return removePath(d.path("pids"))
}

func (s *PidsGroup) GetStats(path string, stats *Stats) error {
	current, err := getCgroupParamUint(path, "pids.current")
	if err != nil {
		return fmt.Errorf("failed to parse pids.current - %s", err)
	}

	maxString, err := getCgroupParamString(path, "pids.max")
	if err != nil {
		return fmt.Errorf("failed to parse pids.max - %s", err)
	}

	// Default if pids.max == "max" is 0 -- which represents "no limit".
	var max uint64
	if maxString != "max" {
		max, err = parseUint(maxString, 10, 64)
		if err != nil {
			return fmt.Errorf("failed to parse pids.max - unable to parse %q as a uint from Cgroup file %q", maxString, filepath.Join(path, "pids.max"))
		}
	}

	stats.PidsStats.Current = current
	stats.PidsStats.Limit = max
	return nil
}
