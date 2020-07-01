package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/shirou/gopsutil/cpu"
	"github.com/shirou/gopsutil/mem"
	"github.com/shirou/gopsutil/process"
)

// CPUTimesStat is a more limited version of cpu.TimesStat to save storage space
type CPUTimesStat struct {
	User   float64 `json:"user"`
	System float64 `json:"system"`
	Idle   float64 `json:"idle"`
	Iowait float64 `json:"iowait"`
	Steal  float64 `json:"steal"`
}

// ProcMemoryInfoStat is a more limited version of process.MemoryInfoStat
type ProcMemoryInfoStat struct {
	RSS  uint64 `json:"rss"`  // bytes
	VMS  uint64 `json:"vms"`  // bytes
	Swap uint64 `json:"swap"` // bytes
}

// ProcNetworkIOStat is a more limited version of net.IOCountersStat
type ProcNetworkIOStat struct {
	BytesSent   uint64 `json:"bytes_sent"`   // number of bytes sent
	BytesRecv   uint64 `json:"bytes_recv"`   // number of bytes received
	PacketsSent uint64 `json:"packets_sent"` // number of packets sent
	PacketsRecv uint64 `json:"packets_recv"` // number of packets received
}

// ProcDiskIOStat exists to override the json field names of proc.IOCountersStat
type ProcDiskIOStat struct {
	ReadCount  uint64 `json:"read_count"`
	WriteCount uint64 `json:"write_count"`
	ReadBytes  uint64 `json:"read_bytes"`
	WriteBytes uint64 `json:"write_bytes"`
}

// MozProcessStat combines existing structs into one.
type MozProcessStat struct {
	Timestamp       int64              `json:"timestamp"`
	Memory          ProcMemoryInfoStat `json:"memory"`  // all uint64
	CPU             CPUTimesStat       `json:"cpu"`     // all float64
	DiskIO          ProcDiskIOStat     `json:"disk"`    // all uint64
	NetworkIO       ProcNetworkIOStat  `json:"network"` // all uint64
	AvailableMemory uint64             `json:"available_memory"`
	// AvailableMemory is kept separate because it's System-wide and must not be summed
}

// ignore network: fifoin fifoout?

// Add the provided MozProcessStat to the current one.
func (m *MozProcessStat) Add(data MozProcessStat) {
	// Maybe there's a way of doing this with reflect
	m.Memory.RSS += data.Memory.RSS
	m.Memory.VMS += data.Memory.VMS
	m.Memory.Swap += data.Memory.Swap

	m.CPU.User += data.CPU.User
	m.CPU.System += data.CPU.System
	m.CPU.Idle += data.CPU.Idle
	m.CPU.Iowait += data.CPU.Iowait
	m.CPU.Steal += data.CPU.Steal

	m.DiskIO.ReadCount += data.DiskIO.ReadCount
	m.DiskIO.WriteCount += data.DiskIO.WriteCount
	m.DiskIO.ReadBytes += data.DiskIO.ReadBytes
	m.DiskIO.WriteBytes += data.DiskIO.WriteBytes

	m.NetworkIO.BytesSent += data.NetworkIO.BytesSent
	m.NetworkIO.BytesRecv += data.NetworkIO.BytesRecv
	m.NetworkIO.PacketsSent += data.NetworkIO.PacketsSent
	m.NetworkIO.PacketsRecv += data.NetworkIO.PacketsRecv
}

// Diff the provided MozProcessStat to the current one.
func (m *MozProcessStat) Diff(data MozProcessStat) {
	// Memory fields are absolute, not a sum, so don't diff those.

	m.CPU.User -= data.CPU.User
	m.CPU.System -= data.CPU.System
	m.CPU.Idle -= data.CPU.Idle
	m.CPU.Iowait -= data.CPU.Iowait
	m.CPU.Steal -= data.CPU.Steal

	m.DiskIO.ReadCount -= data.DiskIO.ReadCount
	m.DiskIO.WriteCount -= data.DiskIO.WriteCount
	m.DiskIO.ReadBytes -= data.DiskIO.ReadBytes
	m.DiskIO.WriteBytes -= data.DiskIO.WriteBytes

	m.NetworkIO.BytesSent -= data.NetworkIO.BytesSent
	m.NetworkIO.BytesRecv -= data.NetworkIO.BytesRecv
	m.NetworkIO.PacketsSent -= data.NetworkIO.PacketsSent
	m.NetworkIO.PacketsRecv -= data.NetworkIO.PacketsRecv
}

// SystemMemoryInfo summarises information about the system memory usage
type SystemMemoryInfo struct {
	TotalMemory uint64 `json:"vmem_total"`
	TotalSwap   uint64 `json:"swap_total"`
}

// SystemInfo summarises information about the instance
type SystemInfo struct {
	MemoryStats      SystemMemoryInfo `json:"memory_stats"`
	CPULogicalCount  int              `json:"cpu_logical_count"`
	CPUPhysicalCount int              `json:"cpu_physical_count"`
}

// StatsOutput controls the output format of the report.
type StatsOutput struct {
	Start      int64            `json:"start"`
	End        int64            `json:"end"`
	Samples    []MozProcessStat `json:"samples"`
	SystemInfo SystemInfo       `json:"system_info"`
}

func findAllProcesses() ([]*process.Process, error) {
	currentPid := os.Getpid()
	myself, err := process.NewProcess(int32(currentPid))
	if err != nil {
		return nil, err
	}
	parent, err := myself.Parent()
	if err != nil {
		return nil, err
	}
	children, _ := parent.Children()
	return children, nil
}

func collectStatsForWithError(proc *process.Process, withError bool) (*MozProcessStat, error) {

	statistics := new(MozProcessStat)

	cpu, err := proc.Times()
	if err != nil {
		if withError {
			log.Printf("CPU Times: %s\n", err)
		}
	} else {
		statistics.CPU = CPUTimesStat{cpu.User, cpu.System, cpu.Idle, cpu.Iowait, cpu.Steal}
		// statistics.CPU = *cpu
	}

	memory, err := proc.MemoryInfo()
	if err != nil {
		if withError {
			log.Printf("MemoryInfo: %s\n", err)
		}
	} else {
		statistics.Memory = ProcMemoryInfoStat{memory.RSS, memory.VMS, memory.Swap}
	}

	diskio, err := proc.IOCounters()
	if err != nil {
		if withError {
			log.Printf("Disk IO: %s\n", err)
		}
	} else {
		statistics.DiskIO = ProcDiskIOStat{diskio.ReadCount, diskio.WriteCount, diskio.ReadBytes, diskio.WriteBytes}
	}

	total := new(ProcNetworkIOStat)
	netio, err := proc.NetIOCounters(false)
	if err != nil {
		if withError {
			log.Printf("Network IO: %s\n", err)
		}
	} else {
		for _, iface := range netio {
			total.BytesSent += iface.BytesSent
			total.BytesRecv += iface.BytesRecv
			total.PacketsSent += iface.PacketsSent
			total.PacketsRecv += iface.PacketsRecv
		}
		statistics.NetworkIO = *total
	}

	return statistics, err
}

func collectStatsFor(proc *process.Process) *MozProcessStat {
	stats, _ := collectStatsForWithError(proc, false)
	return stats
}

// Run the psutil collection.
func collector(fh *os.File) {

	processes, err := findAllProcesses()
	if err != nil {
		fmt.Printf("Unable to find process list, aborting: %v", err)
		return
	}
	statistics := new(MozProcessStat)
	statistics.Timestamp = time.Now().Unix()

	for _, proc := range processes {
		procstats := collectStatsFor(proc)
		statistics.Add(*procstats)
	}

	memory, err := mem.VirtualMemory()
	if err != nil {
		log.Printf("Unable to collect system memory statistics\n")
		return
	}
	statistics.AvailableMemory = memory.Available

	jsonData, err := json.Marshal(statistics)
	if err != nil {
		fmt.Printf("Couldn't format data as json: %v", err)
		return
	}
	_, err = fh.Write(jsonData)
	if err != nil {
		log.Fatalf("Failed writing to output file: %s", err)
	}
	fh.WriteString("\n")
}

func getSystemInfo() *SystemInfo {
	info := new(SystemInfo)
	memInfo := new(SystemMemoryInfo)

	memory, err := mem.VirtualMemory()
	if err != nil {
		log.Fatal(err)
	}
	memInfo.TotalMemory = memory.Total

	swap, err := mem.SwapMemory()
	if err != nil {
		log.Fatal(err)
	}
	memInfo.TotalSwap = swap.Total
	info.MemoryStats = *memInfo

	cpuLogCount, err := cpu.Counts(true)
	if err != nil {
		log.Fatal(err)
	}
	info.CPULogicalCount = cpuLogCount

	cpuPhysCount, err := cpu.Counts(false)
	if err != nil {
		log.Fatal(err)
	}
	info.CPUPhysicalCount = cpuPhysCount
	return info
}

func processOutput(filename string, outputFilename string) {

	fh, err := os.Open(filename)
	if err != nil {
		log.Fatalf("Unable to read temporary file: %s", err)
	}
	defer fh.Close()

	finalStats := new(StatsOutput)
	savedRecord := MozProcessStat{}
	initialValue := true

	var start int64 = math.MaxInt64
	var end int64

	s := bufio.NewScanner(fh)
	for s.Scan() {
		var v MozProcessStat
		if err := json.Unmarshal(s.Bytes(), &v); err != nil {
			log.Fatal("Can't parse json")
		}
		if initialValue {
			savedRecord = v
			initialValue = false
		}
		newSavedRecord := v
		v.Diff(savedRecord)
		finalStats.Samples = append(finalStats.Samples, v)
		savedRecord = newSavedRecord

		if v.Timestamp < start {
			start = v.Timestamp
		}
		if v.Timestamp > end {
			end = v.Timestamp
		}
	}
	if s.Err() != nil {
		log.Fatal("Scan error")
	}

	finalStats.Start = start
	finalStats.End = end
	finalStats.SystemInfo = *getSystemInfo()

	jsonData, err := json.MarshalIndent(finalStats, "", "    ")
	if err != nil {
		log.Fatal(err)
	}
	err = ioutil.WriteFile(outputFilename, jsonData, 0644)

}

func main() {

	outputFilePtr := flag.String("output", "dummy_output_file", "Newline-separated JSON output file")
	collectionInterval := flag.Int("interval", 1.0, "Data collection interval in seconds")
	flag.Parse()

	// flag module doesn't support mandatory arguments, and there's no sensible default for output file.
	requiredArgs := []string{"output"}
	seen := make(map[string]bool)
	flag.Visit(func(f *flag.Flag) { seen[f.Name] = true })
	for _, req := range requiredArgs {
		if !seen[req] {
			log.Fatalf("Required argument -%s missing", req)
		}
	}

	// Log any collection errors once at the start, then ignore them so we don't end up
	// with a spammy log.
	currentPid := os.Getpid()
	myself, err := process.NewProcess(int32(currentPid))
	if err != nil {
		log.Fatalf("%s", err)
	}
	_, err = collectStatsForWithError(myself, true)
	if err != nil {
		log.Printf("Collection will be missing some data: %s", err)
	}

	// Set up interval
	ticker := time.NewTicker(time.Duration(*collectionInterval) * time.Second)
	done := make(chan bool)

	tmpfile, err := ioutil.TempFile("", "")
	if err != nil {
		log.Fatalf("Unable to create temporary file: %s", err)
	}
	// Don't defer closing of the file as we want to process it in this scope.
	defer os.Remove(tmpfile.Name())

	go func() {
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				// TODO replace with temporary file or directory
				collector(tmpfile)
			}

		}

	}()

	// Carry on until we're told to stop.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)

	<-sigs
	ticker.Stop()
	done <- true

	if err := tmpfile.Close(); err != nil {
		log.Fatalf("Unable to close temporary file: %s", err)
	}
	processOutput(tmpfile.Name(), *outputFilePtr)

}
