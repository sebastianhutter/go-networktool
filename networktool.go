/*
  scan specified targets
*/

package main

import (
	"flag"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// struct to hold port scan result
type PortResult struct {
	protocol string
	port     int
	state    bool
	msg      string
}

// struct to hold result of scan
type ScanResult struct {
	target string
	port   []PortResult
	msg    string
}

func ScanPortOfTarget(data chan PortResult, wg *sync.WaitGroup, target string, protocol string, port int) {
	// register waiting group defer function
	defer wg.Done()

	// create address for port check
	address := fmt.Sprintf("%s:%d", target, port)

	// create a PortResult
	var result PortResult

	// add the protocol used for the scan to the port result
	result.protocol = protocol
	result.port = port

	// lets check if the port is valid.
	if port > 65535 && port < 0 {
		result.msg = "invalid port"
		result.state = false
	} else {
		// if valid lets scan the connection with a 5s timeout
		_, err := net.DialTimeout(protocol, address, time.Duration(5)*time.Second)
		// @todo: extend to handle different states, protocols etc/
		// if we received no error message port should be open
		if err == nil {
			result.msg = "port may be open..."
			result.state = true
		} else {
			result.msg = err.Error()
			result.state = false
		}
	}

	// pass result back to the channel
	data <- result
}

func ScanTarget(data chan ScanResult, gwg *sync.WaitGroup, ip string, protocol string, ports []int) {
	// register global waiting group defer action
	defer gwg.Done()

	// create a scanresult
	var result ScanResult
	result.target = ip

	// lets see if the ip address is valid
	// @todo: add dns and ip
	ipaddress := net.ParseIP(ip)
	// if ip is not a valid ipv4 or ipv6 ip
	if ipaddress.To4() == nil || ipaddress.To16() == nil {
		result.msg = "invalid ip"
	} else {
		// create buffered channel with space for all port scan results
		port_results := make(chan PortResult, len(ports))
		var wg sync.WaitGroup
		// execute a scan for all specified ports
		for _, v := range ports {
			wg.Add(1)
			go ScanPortOfTarget(port_results, &wg, ip, protocol, v)
		}
		// wait until all scans completed
		wg.Wait()
		// close the channel
		close(port_results)
		// read results from channel
		for r := range port_results {
			result.port = append(result.port, r)
		}
		// add scan complete message
		result.msg = "scan finished"
	}

	// pass result back to channel
	data <- result
}

func main() {
	// allow to specify a list of hosts and ports to scan
	// scan all specified ports on all specified hosts
	portPtr := flag.String("ports", "80,443,53,445", "comma separated list of ports to scan")
	protocolPtr := flag.String("protocol", "tcp", "protocol for scan - udp / tcp")
	targetPtr := flag.String("targets", "127.0.0.1", "comma separated list of targets to scan")
	flag.Parse()

	targets_to_scan := strings.Split(*targetPtr, ",")
	ports_to_scan_str := strings.Split(*portPtr, ",")
	ports_to_scan := []int{}
	// convert strings  in ports_to_scan to integer
	for _, v := range ports_to_scan_str {
		if v != "" {
			port, _ := strconv.Atoi(v)
			ports_to_scan = append(ports_to_scan, port)
		}
	}

	// add a channel for scan results
	results := make(chan ScanResult, len(targets_to_scan))
	// add the sync wait group to wait for all scans to finish
	var gwg sync.WaitGroup

	// scan all specified targets
	for _, t := range targets_to_scan {
		gwg.Add(1)
		go ScanTarget(results, &gwg, t, *protocolPtr, ports_to_scan)
	}

	//ip := "127.0.0.1"
	//ports := []int{80, 8888, 127}
	//protocol := "tcp"

	// add amount of targets to scan to wait group
	//gwg.Add(1)
	//go ScanTarget(results, &gwg, ip, protocol, ports)

	//msg := <-results
	//fmt.Println(msg)

	// wait until all scans have finished
	gwg.Wait()
	close(results)
	for r := range results {
		fmt.Println(r)
	}
}
