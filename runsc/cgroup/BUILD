package(licenses = ["notice"])  # Apache 2.0

load("@io_bazel_rules_go//go:def.bzl", "go_library")

go_library(
    name = "cgroup",
    srcs = [
        "cgroup_manager.go",
        "cpu.go",
        "cpuset.go",
        "devices.go",
        "hugetlb.go",
        "memory.go",
        "net_cls.go",
        "pids.go",
        "stats.go",
        "utils.go",
    ],
    cgo = True,
    importpath = "gvisor.googlesource.com/gvisor/runsc/cgroup",
    visibility = [
        "//runsc:__subpackages__",
    ],
    deps = [
        "//pkg/log",
        "@com_github_opencontainers_runtime-spec//specs-go:go_default_library",
        "@org_golang_x_sys//unix:go_default_library",
    ],
)