/*
Copyright (c) 2017 VMware, Inc. All Rights Reserved.
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/vmware/govmomi"
	"github.com/vmware/govmomi/simulator"
	"github.com/vmware/govmomi/vim25/soap"
	"github.com/vmware/govmomi/units"
	"github.com/vmware/govmomi/view"
	"github.com/vmware/govmomi/vim25"
	"github.com/vmware/govmomi/vim25/mo"
)

// getEnvString returns string from environment variable.
func getEnvString(v string, def string) string {
	r := os.Getenv(v)
	if r == "" {
		return def
	}

	return r
}

// getEnvBool returns boolean from environment variable.
func getEnvBool(v string, def bool) bool {
	r := os.Getenv(v)
	if r == "" {
		return def
	}

	switch strings.ToLower(r[0:1]) {
	case "t", "y", "1":
		return true
	}

	return false
}

const (
	envURL      = "GOVMOMI_URL"
	envUserName = "GOVMOMI_USERNAME"
	envPassword = "GOVMOMI_PASSWORD"
	envInsecure = "GOVMOMI_INSECURE"
	envHostName = "GOVMOMI_HOST"
	envClusterName = "GOVMOMI_CLUSTER"

)
// Flags
var urlDescription = fmt.Sprintf("ESX or vCenter URL [%s]", envURL)
var urlFlag = flag.String("url", getEnvString(envURL, ""), urlDescription)

var insecureDescription = fmt.Sprintf("Don't verify the server's certificate chain [%s]", envInsecure)
var insecureFlag = flag.Bool("insecure", getEnvBool(envInsecure, false), insecureDescription)

var allDescription = fmt.Sprintf("If present, delete snapshots across all VMs")
var allFlag = flag.Bool("all", false, allDescription)

var hostDescription = fmt.Sprintf("Delete snapshots across VMs on a specific host [%s]", envHostName)
var hostFlag = flag.String("host", getEnvString(envHostName, ""), hostDescription)

var clusterDescription = fmt.Sprintf("Delete snapshots across VMs on a specific cluster [%s]", envClusterName)
var clusterFlag = flag.String("cluster", getEnvString(envClusterName, ""), clusterDescription)

func checkFlags () bool {
	var flags []int
	var sum int = 0

	if (*hostFlag == "") {flags = append(flags, 0)} else {flags = append(flags, 1)}
	if (*clusterFlag == "") {flags = append(flags, 0)} else {flags = append(flags, 1)}
	if !(*allFlag) {flags = append(flags, 0)} else {flags = append(flags, 1)}

	for _ , f := range flags {
		sum += f
	}

	if sum == 1 {
		return true
	} else {
		return false
	}
}


func processOverride(u *url.URL) {
	envUsername := os.Getenv(envUserName)
	envPassword := os.Getenv(envPassword)

	// Override username if provided
	if envUsername != "" {
		var password string
		var ok bool

		if u.User != nil {
			password, ok = u.User.Password()
		}

		if ok {
			u.User = url.UserPassword(envUsername, password)
		} else {
			u.User = url.User(envUsername)
		}
	}

	// Override password if provided
	if envPassword != "" {
		var username string

		if u.User != nil {
			username = u.User.Username()
		}

		u.User = url.UserPassword(username, envPassword)
	}
}

// NewClient creates a govmomi.Client for use in the examples
func NewClient(ctx context.Context) (*govmomi.Client, error) {
	// Parse URL from string
	u, err := soap.ParseURL(*urlFlag)
	if err != nil {
		return nil, err
	}

	// Override username and/or password as required
	processOverride(u)

	// Connect and log in to ESX or vCenter
	return govmomi.NewClient(ctx, u, *insecureFlag)
}

// Run calls f with Client create from the -url flag if provided,
// otherwise runs the example against vcsim.
func Run(f func(context.Context, *vim25.Client) error) {
	flag.Parse()

	var err error
	if *urlFlag == "" || !(checkFlags()) {
		err = simulator.VPX().Run(f)
	} else {
		ctx := context.Background()
		var c *govmomi.Client
		c, err = NewClient(ctx)
		if err == nil {
			err = f(ctx, c.Client)
		}
	}
	if err != nil {
		log.Fatal(err)
	}
}


func main() {
	Run(func(ctx context.Context, c *vim25.Client) error {

		// Create a view of HostSystem objects
		m := view.NewManager(c)

		v, err := m.CreateContainerView(ctx, c.ServiceContent.RootFolder, []string{"HostSystem"}, true)
		if err != nil {
			return err
		}

		defer v.Destroy(ctx)

		// Retrieve summary property for all hosts
		// Reference: http://pubs.vmware.com/vsphere-60/topic/com.vmware.wssdk.apiref.doc/vim.HostSystem.html
		var hss []mo.HostSystem
		err = v.Retrieve(ctx, []string{"HostSystem"}, []string{"summary"}, &hss)
		if err != nil {
			return err
		}

		// Print summary per host (see also: govc/host/info.go)

		tw := tabwriter.NewWriter(os.Stdout, 2, 0, 2, ' ', 0)
		fmt.Fprintf(tw, "Name:\tUsed CPU:\tTotal CPU:\tFree CPU:\tUsed Memory:\tTotal Memory:\tFree Memory:\t\n")

		for _, hs := range hss {
			totalCPU := int64(hs.Summary.Hardware.CpuMhz) * int64(hs.Summary.Hardware.NumCpuCores)
			freeCPU := int64(totalCPU) - int64(hs.Summary.QuickStats.OverallCpuUsage)
			freeMemory := int64(hs.Summary.Hardware.MemorySize) - (int64(hs.Summary.QuickStats.OverallMemoryUsage) * 1024 * 1024)
			fmt.Fprintf(tw, "%s\t", hs.Summary.Config.Name)
			fmt.Fprintf(tw, "%d\t", hs.Summary.QuickStats.OverallCpuUsage)
			fmt.Fprintf(tw, "%d\t", totalCPU)
			fmt.Fprintf(tw, "%d\t", freeCPU)
			fmt.Fprintf(tw, "%s\t", (units.ByteSize(hs.Summary.QuickStats.OverallMemoryUsage))*1024*1024)
			fmt.Fprintf(tw, "%s\t", units.ByteSize(hs.Summary.Hardware.MemorySize))
			fmt.Fprintf(tw, "%d\t", freeMemory)
			fmt.Fprintf(tw, "\n")
		}

		_ = tw.Flush()

		return nil
	})
}