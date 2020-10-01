package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"errors"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"github.com/hashicorp/go-version"
)

const (
	namespace        = "powerdns"
	apiInfoEndpoint  = "servers/localhost"
	apiStatsEndpoint = "servers/localhost/statistics?includerings=false"
)

var (
	client = &http.Client{
		Transport: &http.Transport{
			Dial: func(netw, addr string) (net.Conn, error) {
				c, err := net.DialTimeout(netw, addr, 5*time.Second)
				if err != nil {
					return nil, err
				}
				if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					return nil, err
				}
				return c, nil
			},
		},
	}
)

// ServerInfo is used to parse JSON data from 'server/localhost' endpoint
type ServerInfo struct {
	Kind       string `json:"type"`
	ID         string `json:"id"`
	URL        string `json:"url"`
	DaemonType string `json:"daemon_type"`
	Version    string `json:"version"`
	ConfigUrl  string `json:"config_url"`
	ZonesUrl   string `json:"zones_url"`
}

// Stats entry is a container for a realy statistic item. The Item property contains the actual item.
type StatsEntry struct {
    Item interface{}
}

// Contains a primitive statistic item that contains just one value
type StatisticItem struct {
	Name  string  `json:"name"`
	Kind  string  `json:"type"`
	Value float64 `json:"value,string"`
}

// Contains a ring statistic item which holds up to Size entries at max. For every entry, it holds a counter value.
// Number and name of of the items can change during operation.
type RingStatisticItem struct {
	Name  string  `json:"name"`
	Kind  string  `json:"type"`
	Size int64 `json:"size,string"`
	Value []StatisticItemEntry `json:"value,string"`
}

// Contains a map statistic item which holds multiple values with static keys.
type MapStatisticItem struct {
	Name  string  `json:"name"`
	Kind  string  `json:"type"`
	Value []StatisticItemEntry `json:"value,string"`
}

// Actual Values of ring and map statistic items
type StatisticItemEntry struct {
	Name  string  `json:"name"`
	Value float64 `json:"value,string"`
}

// Used to dynamically parse statistic items based on their type
func (d *StatsEntry) UnmarshalJSON(data []byte) error {
    var typ struct {
        Kind string `json:"type"`
    }

    if err := json.Unmarshal(data, &typ); err != nil {
        return err
    }

    switch typ.Kind {
    case "StatisticItem":
        d.Item = new(StatisticItem)
    case "RingStatisticItem":
        d.Item = new(RingStatisticItem)
    case "MapStatisticItem":
        d.Item = new(MapStatisticItem)
	default:
		return errors.New("Unsupported Statistic Type")
    }

    return json.Unmarshal(data, d.Item)
}

// Exporter collects PowerDNS stats from the given HostURL and exports them using
// the prometheus metrics package.
type Exporter struct {
	HostURL    *url.URL
	ServerType string
	ApiKey     string
	mutex      sync.RWMutex

	up                prometheus.Gauge
	totalScrapes      prometheus.Counter
	jsonParseFailures prometheus.Counter
	gaugeMetrics      map[int]prometheus.Gauge
	counterMetrics    map[int]*prometheus.Desc
	simpleCounterMetrics    map[int]*prometheus.Desc
	gaugeDefs         []gaugeDefinition
	counterDefs       []counterDefinition
	simpleCounterDefs []simpleCounterDefinition
	client            *http.Client
}

func newGaugeMetric(serverType, metricName, docString string) prometheus.Gauge {
	return prometheus.NewGauge(
		prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: serverType,
			Name:      metricName,
			Help:      docString,
		},
	)
}

// NewExporter returns an initialized Exporter.
func NewExporter(apiKey, serverType string, serverVersion *version.Version, hostURL *url.URL) *Exporter {
	var gaugeDefs []gaugeDefinition
	var counterDefs []counterDefinition
	var simpleCounterDefs []simpleCounterDefinition

	gaugeMetrics := make(map[int]prometheus.Gauge)
	counterMetrics := make(map[int]*prometheus.Desc)
	simpleCounterMetrics := make(map[int]*prometheus.Desc)

	simpleCounterDefs = []simpleCounterDefinition {}
	switch serverType {
	case "recursor":
		gaugeDefs = recursorGaugeDefs
		counterDefs = recursorCounterDefs
	case "authoritative":
		gaugeDefs = authoritativeGaugeDefs
		counterDefs = authoritativeCounterDefs
		var v42, _ = version.NewVersion("4.2.0")
		if serverVersion.GreaterThanOrEqual(v42) {
			simpleCounterDefs = authoritativeSimpleCounterDefs
		}
	case "dnsdist":
		gaugeDefs = dnsdistGaugeDefs
		counterDefs = dnsdistCounterDefs
	}

	for _, def := range gaugeDefs {
		gaugeMetrics[def.id] = newGaugeMetric(serverType, def.name, def.desc)
	}

	for _, def := range counterDefs {
		counterMetrics[def.id] = prometheus.NewDesc(
			prometheus.BuildFQName(
				namespace,
				serverType,
				def.name,
			),
			def.desc,
			[]string{def.label},
			nil,
		)
	}

	for _, def := range simpleCounterDefs {
		simpleCounterMetrics[def.id] = prometheus.NewDesc(
			prometheus.BuildFQName(
				namespace,
				serverType,
				def.name,
			),
			def.desc,
			[]string{def.labelName},
			nil,
		)
	}

	return &Exporter{
		HostURL:    hostURL,
		ServerType: serverType,
		ApiKey:     apiKey,
		up: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: serverType,
			Name:      "up",
			Help:      "Was the last scrape of PowerDNS successful.",
		}),
		totalScrapes: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: serverType,
			Name:      "exporter_total_scrapes",
			Help:      "Current total PowerDNS scrapes.",
		}),
		jsonParseFailures: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: serverType,
			Name:      "exporter_json_parse_failures",
			Help:      "Number of errors while parsing PowerDNS JSON stats.",
		}),
		gaugeMetrics:   gaugeMetrics,
		counterMetrics: counterMetrics,
		simpleCounterMetrics: simpleCounterMetrics,
		gaugeDefs:      gaugeDefs,
		counterDefs:    counterDefs,
		simpleCounterDefs: simpleCounterDefs,
	}
}

// Describe describes all the metrics ever exported by the PowerDNS exporter. It
// implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	for _, m := range e.counterMetrics {
		ch <- m
	}
	for _, m := range e.simpleCounterMetrics {
		ch <- m
	}
	for _, m := range e.gaugeMetrics {
		ch <- m.Desc()
	}
	ch <- e.up.Desc()
	ch <- e.totalScrapes.Desc()
	ch <- e.jsonParseFailures.Desc()
}

// Collect fetches the stats from configured PowerDNS API URI and delivers them
// as Prometheus metrics. It implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	e.mutex.Lock()
	defer e.mutex.Unlock()

	stats := e.scrape()
	ch <- e.up
	ch <- e.totalScrapes
	ch <- e.jsonParseFailures

	e.collectMetrics(ch, stats)
}

func (e *Exporter) scrape() []StatsEntry {
	e.totalScrapes.Inc()

	var data []StatsEntry
	url := apiURL(e.HostURL, apiStatsEndpoint)
	err := getJSON(url, e.ApiKey, &data)
	if err != nil {
		e.up.Set(0)
		e.jsonParseFailures.Inc()
		log.Errorf("Error scraping PowerDNS: %v", err)
		return nil
	}

	e.up.Set(1)
	return data
}

func (e *Exporter) collectMetrics(ch chan<- prometheus.Metric, stats []StatsEntry) {
	statsMap := make(map[string]float64)
	simpleStatsMap := make(map[string][]StatisticItemEntry)
	for _, s := range stats {
		switch item := s.Item.(type) {
		case *StatisticItem:
			statsMap[item.Name] = item.Value
		case *RingStatisticItem:
			simpleStatsMap[item.Name] = item.Value
		case *MapStatisticItem:
			simpleStatsMap[item.Name] = item.Value
		}
	}
	if len(statsMap) == 0 {
		return
	}

	for _, def := range e.gaugeDefs {
		if value, ok := statsMap[def.key]; ok {
			// latency gauges need to be converted from microseconds to seconds
			if strings.HasSuffix(def.key, "latency") {
				value = value / 1000000
			}
			e.gaugeMetrics[def.id].Set(value)
			ch <- e.gaugeMetrics[def.id]
		} else {
			log.Errorf("Expected PowerDNS stats key not found: %s", def.key)
			e.jsonParseFailures.Inc()
		}
	}

	for _, def := range e.simpleCounterDefs {
		if items, ok := simpleStatsMap[def.key]; ok {
			for _, item := range items {
				ch <- prometheus.MustNewConstMetric(e.simpleCounterMetrics[def.id], prometheus.CounterValue, item.Value, item.Name)
			}
		} else {
			log.Errorf("Expected PowerDNS stats key not found: %s", def.key)
			e.jsonParseFailures.Inc()
		}
	}

	for _, def := range e.counterDefs {
		for key, label := range def.labelMap {
			if value, ok := statsMap[key]; ok {
				ch <- prometheus.MustNewConstMetric(e.counterMetrics[def.id], prometheus.CounterValue, float64(value), label)
			} else {
				log.Errorf("Expected PowerDNS stats key not found: %s", key)
				e.jsonParseFailures.Inc()
			}
		}
	}

	if e.ServerType == "recursor" {
		h, err := makeRecursorRTimeHistogram(statsMap)
		if err != nil {
			log.Errorf("Could not create response time histogram: %v", err)
			return
		}
		ch <- h
	}
}

func getServerInfo(hostURL *url.URL, apiKey string) (*ServerInfo, error) {
	var info ServerInfo
	url := apiURL(hostURL, apiInfoEndpoint)
	err := getJSON(url, apiKey, &info)
	if err != nil {
		return nil, err
	}

	return &info, nil
}

func getJSON(url, apiKey string, data interface{}) error {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return err
	}

	req.Header.Add("X-API-Key", apiKey)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		content, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		return fmt.Errorf(string(content))
	}

	if err := json.NewDecoder(resp.Body).Decode(data); err != nil {
		return err
	}

	return nil
}

func apiURL(hostURL *url.URL, path string) string {
	endpointURI, _ := url.Parse(path)
	u := hostURL.ResolveReference(endpointURI)
	return u.String()
}

func main() {
	var (
		listenAddress = flag.String("listen-address", ":9120", "Address to listen on for web interface and telemetry.")
		metricsPath   = flag.String("metric-path", "/metrics", "Path under which to expose metrics.")
		apiURL        = flag.String("api-url", "http://localhost:8001/", "Base-URL of PowerDNS authoritative server/recursor API.")
		apiKey        = flag.String("api-key", "", "PowerDNS API Key")
	)
	flag.Parse()

	hostURL, err := url.Parse(*apiURL)
	if err != nil {
		log.Fatalf("Error parsing api-url: %v", err)
	}

	server, err := getServerInfo(hostURL, *apiKey)
	if err != nil {
		log.Fatalf("Could not fetch PowerDNS server info: %v", err)
	}

	version, err := version.NewVersion(server.Version)
	if err != nil {
		log.Fatalf("Could not parse PowerDNS server version: %v", err)
	}

	exporter := NewExporter(*apiKey, server.DaemonType, version, hostURL)
	prometheus.MustRegister(exporter)

	log.Infof("Starting Server: %s", *listenAddress)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
             <head><title>PowerDNS Exporter</title></head>
             <body>
             <h1>PowerDNS Exporter</h1>
             <p><a href='` + *metricsPath + `'>Metrics</a></p>
             </body>
             </html>`))
	})

	go func() {
		log.Fatal(http.ListenAndServe(*listenAddress, nil))
	}()

	<-stop
}
