// +build linux

package cgroup

import (
	"strconv"
)

type NetClsGroup struct {
}

func (s *NetClsGroup) Name() string {
	return "net_cls"
}

func (s *NetClsGroup) Apply(d *cgroupData) error {
	_, err := d.join("net_cls")
	if err != nil && !IsNotFound(err) {
		return err
	}
	return nil
}

func (s *NetClsGroup) Set(path string, cgroup *Cgroup) error {
	if cgroup.Resources.NetClsClassid != 0 {
		if err := writeFile(path, "net_cls.classid", strconv.FormatUint(uint64(cgroup.Resources.NetClsClassid), 10)); err != nil {
			return err
		}
	}

	return nil
}

func (s *NetClsGroup) Remove(d *cgroupData) error {
	return removePath(d.path("net_cls"))
}

func (s *NetClsGroup) GetStats(path string, stats *Stats) error {
	return nil
}
