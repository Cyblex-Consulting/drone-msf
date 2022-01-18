package main

import (
        "encoding/json"
        "flag"
        "fmt"
        "io/ioutil"
        "log"
        "net/url"
        "os"
        "strings"
        "strconv"

        "github.com/lair-framework/api-server/client"
        "github.com/lair-framework/go-lair"
        "github.com/lair-framework/go-msf"
)

const (
        version  = "1.0.0"
        tool     = "metasploit"
        usage    = `
Parses an XML file exported from metasploit with db_export into a lair project.

Usage:
  drone-msf [options] <id> <filename>
  export LAIR_ID=<id>; drone-msf [options] <filename>
Options:
  -v              show version and exit
  -h              show usage and exit
  -k              allow insecure SSL connections
  -force-ports    disable data protection in the API server for excessive ports
  -limit-hosts    only import hosts that have listening ports
  -tags           a comma separated list of tags to add to every host that is imported
`
)

func buildProject(data *msf.Data, projectID string, tags []string) (*lair.Project, error) {
        project := &lair.Project{}
        project.ID = projectID
        project.Tool = tool
        project.Commands = append(project.Commands, lair.Command{Tool: tool, Command: ""})
        for _, h := range data.Hosts {
                host := &lair.Host{Tags: tags}
                if h.State != "alive" {
                        continue
                }

                host.IPv4 = h.Address
                host.MAC = h.Mac
                host.Hostnames = append(host.Hostnames, h.Name)
                if h.Comments != "" {
                        hnote := &lair.Note{Title: "Comments", Content: h.Comments, LastModifiedBy: tool}
                        host.Notes = append(host.Notes, *hnote)
                }

                for _, svc := range h.Services {
                        service := lair.Service{}
                        service.Port, _ = strconv.Atoi(svc.Port)
                        service.Protocol = svc.Proto
                        if svc.State != "open" {
                                continue
                        }
                        if svc.Name != "" {
                                service.Service = svc.Name
                                service.Product = "Unknown"
                                if svc.Info != "" {
                                        service.Product = svc.Info
                                }
                        }
                        host.Services = append(host.Services, service)
                }
                os := lair.OS{}
                oos.Tool = "Metasploit"
                os.Weight = 1
                os.Fingerprint = h.OsName + " " + h.OsFlavor + " " + h.OsSp + " " + h.OsLang + " " + h.Arch
                host.OS = os


                project.Hosts = append(project.Hosts, *host)
        }

        return project, nil
}


func main() {
        showVersion := flag.Bool("v", false, "")
        insecureSSL := flag.Bool("k", false, "")
        forcePorts := flag.Bool("force-ports", false, "")
        limitHosts := flag.Bool("limit-hosts", false, "")
        tags := flag.String("tags", "", "")
        flag.Usage = func() {
                fmt.Println(usage)
        }
        flag.Parse()
        if *showVersion {
                log.Println(version)
                os.Exit(0)
        }
        lairURL := os.Getenv("LAIR_API_SERVER")
        if lairURL == "" {
                log.Fatal("Fatal: Missing LAIR_API_SERVER environment variable")
        }
        lairPID := os.Getenv("LAIR_ID")

        var filename string
        switch len(flag.Args()) {
        case 2:
                lairPID = flag.Arg(0)
                filename = flag.Arg(1)
        case 1:
                filename = flag.Arg(0)
        default:
                log.Fatal("Fatal: Missing required argument")
        }
        if lairPID == "" {
                log.Fatal("Fatal: Missing LAIR_ID")
        }
        u, err := url.Parse(lairURL)
        if err != nil {
                log.Fatalf("Fatal: Error parsing LAIR_API_SERVER URL. Error %s", err.Error())
        }
        if u.User == nil {
                log.Fatal("Fatal: Missing username and/or password")
        }
        user := u.User.Username()
        pass, _ := u.User.Password()
        if user == "" || pass == "" {
                log.Fatal("Fatal: Missing username and/or password")
        }
        c, err := client.New(&client.COptions{
                User:               user,
                Password:           pass,
                Host:               u.Host,
                Scheme:             u.Scheme,
                InsecureSkipVerify: *insecureSSL,
        })
        if err != nil {
                log.Fatalf("Fatal: Error setting up client. Error %s", err.Error())
        }
        data, err := ioutil.ReadFile(filename)
        if err != nil {
                log.Fatalf("Fatal: Could not open file. Error %s", err.Error())
        }
        hostTags := []string{}
        if *tags != "" {
                hostTags = strings.Split(*tags, ",")
        }
        msfData, err := msf.Parse(data)
        if err != nil {
                log.Fatalf("Fatal: Error parsing metasploit. Error %s", err.Error())
        }
        project, err := buildProject(msfData, lairPID, hostTags)
        if err != nil {
                log.Fatalf("Fatal: Error building project. Error %s", err.Error())
        }
        res, err := c.ImportProject(&client.DOptions{ForcePorts: *forcePorts, LimitHosts: *limitHosts}, project)
        if err != nil {
                log.Fatalf("Fatal: Unable to import project. Error %s", err.Error())
        }
        defer res.Body.Close()
        droneRes := &client.Response{}
        body, err := ioutil.ReadAll(res.Body)
        if err != nil {
                log.Fatalf("Fatal: Error %s", err.Error())
        }
        if err := json.Unmarshal(body, droneRes); err != nil {
                log.Fatalf("Fatal: Could not unmarshal JSON. Error %s", err.Error())
        }
        if droneRes.Status == "Error" {
                log.Fatalf("Fatal: Import failed. Error %s", droneRes.Message)
        }
        log.Println("Success: Operation completed successfully")
}
