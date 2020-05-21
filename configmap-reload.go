package main

import (
	"bufio"
	"flag"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"time"

	fsnotify "github.com/fsnotify/fsnotify"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const namespace = "configmap_reload"

var (
	volumeDirs        volumeDirsFlag
	webhook           webhookFlag
	webhookMethod     = flag.String("webhook-method", "POST", "the HTTP method url to use to send the webhook")
	webhookStatusCode = flag.Int("webhook-status-code", 200, "the HTTP status code indicating successful triggering of reload")
	listenAddress     = flag.String("web.listen-address", ":9533", "Address to listen on for web interface and telemetry.")
	metricPath        = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")
	execPath          = flag.String("exec-path", "", "the path to be executed")
	entryExec         = flag.String("entry-path", "", "the path to be executed when pod is up")

	lastReloadError = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "last_reload_error",
		Help:      "Whether the last reload resulted in an error (1 for error, 0 for success)",
	}, []string{"webhook"})
	requestDuration = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: namespace,
		Name:      "last_request_duration_seconds",
		Help:      "Duration of last webhook request",
	}, []string{"webhook"})
	successReloads = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "success_reloads_total",
		Help:      "Total success reload calls",
	}, []string{"webhook"})
	requestErrorsByReason = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "request_errors_total",
		Help:      "Total request errors by reason",
	}, []string{"webhook", "reason"})
	watcherErrors = prometheus.NewCounter(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "watcher_errors_total",
		Help:      "Total filesystem watcher errors",
	})
	requestsByStatusCode = prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: namespace,
		Name:      "requests_total",
		Help:      "Total requests by response status code",
	}, []string{"webhook", "status_code"})
)

func init() {
	prometheus.MustRegister(lastReloadError)
	prometheus.MustRegister(requestDuration)
	prometheus.MustRegister(successReloads)
	prometheus.MustRegister(requestErrorsByReason)
	prometheus.MustRegister(watcherErrors)
	prometheus.MustRegister(requestsByStatusCode)
}

func main() {
	flag.Var(&volumeDirs, "volume-dir", "the config map volume directory to watch for updates; may be used multiple times")
	flag.Var(&webhook, "webhook-url", "the url to send a request to when the specified config map volume directory has been updated")
	flag.Parse()

	if len(volumeDirs) < 1 {
		log.Println("Missing volume-dir")
		log.Println()
		flag.Usage()
		os.Exit(1)
	}

	actionable := false

	if len(webhook) > 1 {
		actionable = true
	}

	if len(*execPath) > 1 {
		if _, err := os.Stat(*execPath); err != nil {
			if os.IsNotExist(err) {
				log.Println("Missing executable in path")
			} else {
				log.Println(err.Error())
			}
			log.Println()
			flag.Usage()
			os.Exit(1)
		}
		actionable = true
	}

	if !actionable {
		log.Println("Missing webhook-url & exec-path")
		log.Println()
		flag.Usage()
		os.Exit(1)
	}

	if len(*entryExec) > 1 {
		if _, err := os.Stat(*entryExec); err != nil {
			if os.IsNotExist(err) {
				log.Println("Missing executable in path")
			} else {
				log.Println(err.Error())
			}
			log.Println()
			flag.Usage()
			os.Exit(1)
		}
		cmd := exec.Command(*entryExec)
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			log.Println("error:", err)
		}
		log.Println("Executing entry file...")
		go func() {
			scanner := bufio.NewScanner(stdout)
			for scanner.Scan() {
				log.Println(scanner.Text())
			}
		}()
		if err = cmd.Run(); err == nil {
			log.Printf("Executed with error: %v", err)
			log.Println()
		}
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Fatal(err)
	}
	defer watcher.Close()

	go func() {
		for {
			select {
			case event := <-watcher.Events:
				if !isValidEvent(event) {
					continue
				}
				log.Println("config map updated")
				cmd := exec.Command(*execPath)
				stdout, err := cmd.StdoutPipe()
				if err != nil {
					log.Println("error:", err)
				}
				log.Println("Executing file...")
				go func() {
					scanner := bufio.NewScanner(stdout)
					for scanner.Scan() {
						log.Println(scanner.Text())
					}
				}()
				if err = cmd.Run(); err == nil {
					log.Printf("Executed with error: %v", err)
					log.Println()
				}
				for _, h := range webhook {
					begun := time.Now()
					req, err := http.NewRequest(*webhookMethod, h.String(), nil)
					if err != nil {
						setFailureMetrics(h.String(), "client_request_create")
						log.Println("error:", err)
						continue
					}
					userInfo := h.User
					if userInfo != nil {
						if password, passwordSet := userInfo.Password(); passwordSet {
							req.SetBasicAuth(userInfo.Username(), password)
						}
					}
					resp, err := http.DefaultClient.Do(req)
					if err != nil {
						setFailureMetrics(h.String(), "client_request_do")
						log.Println("error:", err)
						continue
					}
					resp.Body.Close()
					requestsByStatusCode.WithLabelValues(h.String(), strconv.Itoa(resp.StatusCode)).Inc()
					if resp.StatusCode != *webhookStatusCode {
						setFailureMetrics(h.String(), "client_response")
						log.Println("error:", "Received response code", resp.StatusCode, ", expected", *webhookStatusCode)
						continue
					}
					setSuccessMetrict(h.String(), begun)
					log.Println("successfully triggered reload")
				}
			case err := <-watcher.Errors:
				watcherErrors.Inc()
				log.Println("error:", err)
			}
		}
	}()

	for _, d := range volumeDirs {
		log.Printf("Watching directory: %q", d)
		err = watcher.Add(d)
		if err != nil {
			log.Fatal(err)
		}
	}

	log.Fatal(serverMetrics(*listenAddress, *metricPath))
}

func setFailureMetrics(h, reason string) {
	requestErrorsByReason.WithLabelValues(h, reason).Inc()
	lastReloadError.WithLabelValues(h).Set(1.0)
}

func setSuccessMetrict(h string, begun time.Time) {
	requestDuration.WithLabelValues(h).Set(time.Since(begun).Seconds())
	successReloads.WithLabelValues(h).Inc()
	lastReloadError.WithLabelValues(h).Set(0.0)
}

func isValidEvent(event fsnotify.Event) bool {
	if event.Op&fsnotify.Create != fsnotify.Create {
		return false
	}
	if filepath.Base(event.Name) != "..data" {
		return false
	}
	return true
}

func serverMetrics(listenAddress, metricsPath string) error {
	http.Handle(metricsPath, promhttp.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`
			<html>
			<head><title>ConfigMap Reload Metrics</title></head>
			<body>
			<h1>ConfigMap Reload</h1>
			<p><a href='` + metricsPath + `'>Metrics</a></p>
			</body>
			</html>
		`))
	})
	return http.ListenAndServe(listenAddress, nil)
}

type volumeDirsFlag []string

type webhookFlag []*url.URL

func (v *volumeDirsFlag) Set(value string) error {
	*v = append(*v, value)
	return nil
}

func (v *volumeDirsFlag) String() string {
	return fmt.Sprint(*v)
}

func (v *webhookFlag) Set(value string) error {
	u, err := url.Parse(value)
	if err != nil {
		return fmt.Errorf("invalid URL: %v", err)
	}
	*v = append(*v, u)
	return nil
}

func (v *webhookFlag) String() string {
	return fmt.Sprint(*v)
}
