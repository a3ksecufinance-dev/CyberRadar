package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
)

// A number without the machine that produced it is not a measurement, it is a
// claim. Everything in this file exists so that the three figures can never be
// quoted on their own.

type machine struct {
	CPUModel  string
	CPUs      int
	CPUQuota  string // what the cgroup allows, when it allows less than the cores
	MemTotal  string
	Kernel    string
	GoVersion string
	// Shared says the measurement ran beside the platform it was measuring,
	// which is the normal case for this tool and the first thing that has to
	// be said about its numbers.
	Shared bool
}

func describeMachine(shared bool) machine {
	m := machine{
		CPUs:      runtime.NumCPU(),
		GoVersion: runtime.Version(),
		Shared:    shared,
		CPUModel:  firstFieldFrom("/proc/cpuinfo", "model name"),
		MemTotal:  humanKB(firstFieldFrom("/proc/meminfo", "MemTotal")),
		Kernel:    strings.TrimSpace(readAll("/proc/sys/kernel/osrelease")),
		CPUQuota:  cgroupQuota(),
	}
	if m.CPUModel == "" {
		m.CPUModel = runtime.GOARCH
	}
	return m
}

func (m machine) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "  processeur       %s × %d\n", m.CPUModel, m.CPUs)
	if m.CPUQuota != "" {
		fmt.Fprintf(&b, "  quota cgroup     %s\n", m.CPUQuota)
	}
	fmt.Fprintf(&b, "  mémoire          %s\n", m.MemTotal)
	fmt.Fprintf(&b, "  noyau            %s\n", m.Kernel)
	fmt.Fprintf(&b, "  Go               %s\n", m.GoVersion)
	if m.Shared {
		fmt.Fprintf(&b, "  disposition      les 29 services, Kafka, PostgreSQL, ClickHouse, Redis et Neo4j\n")
		fmt.Fprintf(&b, "                   tournent sur cette même machine, et le banc aussi\n")
	}
	return b.String()
}

// firstFieldFrom reads "key : value" lines, which is the shape of both
// /proc/cpuinfo and /proc/meminfo.
func firstFieldFrom(path, key string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close() //nolint:errcheck // read-only
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		name, value, ok := strings.Cut(line, ":")
		if ok && strings.TrimSpace(name) == key {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func readAll(path string) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return string(raw)
}

func humanKB(s string) string {
	fields := strings.Fields(s)
	if len(fields) == 0 {
		return s
	}
	kb, err := strconv.ParseFloat(fields[0], 64)
	if err != nil {
		return s
	}
	return fmt.Sprintf("%.1f Gio", kb/1024/1024)
}

// cgroupQuota reports the CPU the cgroup allows when that is less than the
// cores the kernel reports. A container with four cores and a quota of two is
// a two-core machine, and a figure measured on it is a two-core figure.
func cgroupQuota() string {
	// cgroup v2: "max 100000" means no limit; "200000 100000" means 2 CPUs.
	if raw := strings.Fields(readAll("/sys/fs/cgroup/cpu.max")); len(raw) == 2 {
		if raw[0] == "max" {
			return ""
		}
		quota, err1 := strconv.ParseFloat(raw[0], 64)
		period, err2 := strconv.ParseFloat(raw[1], 64)
		if err1 == nil && err2 == nil && period > 0 {
			return fmt.Sprintf("%.2f CPU", quota/period)
		}
	}
	// cgroup v1: -1 means no limit.
	q := strings.TrimSpace(readAll("/sys/fs/cgroup/cpu/cpu.cfs_quota_us"))
	p := strings.TrimSpace(readAll("/sys/fs/cgroup/cpu/cpu.cfs_period_us"))
	quota, err1 := strconv.ParseFloat(q, 64)
	period, err2 := strconv.ParseFloat(p, 64)
	if err1 == nil && err2 == nil && quota > 0 && period > 0 {
		return fmt.Sprintf("%.2f CPU", quota/period)
	}
	return ""
}
