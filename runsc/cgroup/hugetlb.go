// +build linux

package cgroup

import (
	"fmt"
	"strconv"
	"strings"
)

type HugetlbGroup struct {
}

func (s *HugetlbGroup) Name() string {
	return "hugetlb"
}

func (s *HugetlbGroup) Apply(d *cgroupData) error {
	_, err := d.join("hugetlb")
	if err != nil && !IsNotFound(err) {
		return err
	}
	return nil
}

func (s *HugetlbGroup) Set(path string, cgroup *Cgroup) error {
	for _, hugetlb := range cgroup.Resources.HugetlbLimit {
		if err := writeFile(path, strings.Join([]string{"hugetlb", hugetlb.Pagesize, "limit_in_bytes"}, "."), strconv.FormatUint(hugetlb.Limit, 10)); err != nil {
			return err
		}
	}

	return nil
}

func (s *HugetlbGroup) Remove(d *cgroupData) error {
	return removePath(d.path("hugetlb"))
}

func (s *HugetlbGroup) GetStats(path string, stats *Stats) error {
	hugetlbStats := HugetlbStats{}
	for _, pageSize := range HugePageSizes {
		usage := strings.Join([]string{"hugetlb", pageSize, "usage_in_bytes"}, ".")
		value, err := getCgroupParamUint(path, usage)
		if err != nil {
			return fmt.Errorf("failed to parse %s - %v", usage, err)
		}
		hugetlbStats.Usage = value

		maxUsage := strings.Join([]string{"hugetlb", pageSize, "max_usage_in_bytes"}, ".")
		value, err = getCgroupParamUint(path, maxUsage)
		if err != nil {
			return fmt.Errorf("failed to parse %s - %v", maxUsage, err)
		}
		hugetlbStats.MaxUsage = value

		failcnt := strings.Join([]string{"hugetlb", pageSize, "failcnt"}, ".")
		value, err = getCgroupParamUint(path, failcnt)
		if err != nil {
			return fmt.Errorf("failed to parse %s - %v", failcnt, err)
		}
		hugetlbStats.Failcnt = value

		stats.HugetlbStats[pageSize] = hugetlbStats
	}

	return nil
}
