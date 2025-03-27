package main

import (
	"bytes"
	"encoding/json"
	"flag" // Import the flag package
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Default values (can be overridden by flags)
const (
	defaultListenAddr = ":20003"
	defaultTargetURL  = "http://localhost:20004"
	maxBodyPrintSize  = 1024 * 10 // Limit printed body size to 10KB
)

// --- ANSI Color Codes ---
const (
	colorReset   = "\033[0m"
	colorRed     = "\033[31m"
	colorGreen   = "\033[32m"
	colorYellow  = "\033[33m"
	colorBlue    = "\033[34m"
	colorMagenta = "\033[35m"
	colorCyan    = "\033[36m"
	colorWhite   = "\033[37m"
	colorGray    = "\033[90m"
	colorBold    = "\033[1m"
)

// --- Configuration for Header Omission ---
var headersToOmit = map[string]struct{}{
	"x-forwarded-proto": {},
	"cf-ipcountry":      {},
	"cf-ray":            {},
	"x-real-ip":         {},
	"accept-encoding":   {},
	"cf-visitor":        {},
	"cf-connecting-ip":  {},
	"cdn-loop":          {},
	"x-forwarded-for":   {},
}

const authorizationHeader = "Authorization"

type logEntry struct {
	Timestamp       time.Time
	ClientAddr      string
	RequestMethod   string
	RequestURL      *url.URL
	RequestProto    string
	RequestHost     string
	RequestHeaders  http.Header
	RequestBody     []byte
	StatusCode      int
	ResponseHeaders http.Header
	ResponseBody    []byte
	Duration        time.Duration
}

// --- Global variables to hold flag values ---
var (
	listenAddr string
	targetURL  string
)

func main() {
	// --- Define command-line flags ---
	flag.StringVar(&listenAddr, "listen", defaultListenAddr, "Address and port for the proxy to listen on")
	flag.StringVar(&targetURL, "target", defaultTargetURL, "URL of the target server to forward requests to")
	flag.Parse() // Parse the flags from the command line

	// Normalize headersToOmit keys
	normalizedHeadersToOmit := make(map[string]struct{})
	for header := range headersToOmit {
		normalizedHeadersToOmit[strings.ToLower(header)] = struct{}{}
	}
	headersToOmit = normalizedHeadersToOmit

	// --- Use the targetURL from the flag ---
	targetURLParsed, err := url.Parse(targetURL)
	if err != nil {
		log.Fatalf("FATAL: Invalid target server URL %q: %v", targetURL, err)
	}
	// Ensure target has a scheme
	if targetURLParsed.Scheme == "" {
		log.Fatalf("FATAL: Target URL %q must have a scheme (e.g., http or https)", targetURL)
	}

	proxyHandler := func(w http.ResponseWriter, r *http.Request) {
		startTime := time.Now()
		entry := &logEntry{
			Timestamp:      startTime,
			ClientAddr:     r.RemoteAddr,
			RequestMethod:  r.Method,
			RequestURL:     r.URL,
			RequestProto:   r.Proto,
			RequestHost:    r.Host,
			RequestHeaders: r.Header.Clone(),
		}

		// --- Read Request Body ---
		var requestBodyBytes []byte
		if r.Body != nil && r.ContentLength != 0 {
			requestBodyBytes, err = io.ReadAll(r.Body)
			if err != nil {
				log.Printf("%sERROR: Failed reading request body: %v%s", colorRed, err, colorReset)
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				return
			}
			r.Body.Close()
			r.Body = io.NopCloser(bytes.NewBuffer(requestBodyBytes))
			entry.RequestBody = requestBodyBytes
		}

		// --- Print Incoming Request ---
		fmt.Printf("\n%s--- Incoming Request ---%s\n", colorBold+colorCyan, colorReset)
		fmt.Printf("%sTime:%s %s\n", colorGray, colorReset, entry.Timestamp.Format(time.RFC3339))
		fmt.Printf("%sFrom:%s %s\n", colorGray, colorReset, entry.ClientAddr)
		fmt.Printf("%sRequest:%s %s%s%s %s%s%s %s%s%s\n",
			colorGray, colorReset,
			colorBold+colorGreen, entry.RequestMethod, colorReset,
			colorBold+colorBlue, entry.RequestURL.Path, colorReset,
			colorGray, entry.RequestProto, colorReset,
		)
		fmt.Printf("%sHost:%s %s\n", colorGray, colorReset, entry.RequestHost)
		printQueryParams(entry.RequestURL.Query())
		printHeaders("Request Headers:", entry.RequestHeaders)
		printBody("Request Body:", entry.RequestHeaders.Get("Content-Type"), entry.RequestBody)
		fmt.Printf("%s------------------------%s\n", colorBold+colorCyan, colorReset)

		// --- Prepare & Send Forwarded Request ---
		targetReqURL := *targetURLParsed
		targetReqURL.Path = singleJoiningSlash(targetURLParsed.Path, entry.RequestURL.Path)
		targetReqURL.RawQuery = entry.RequestURL.RawQuery

		proxyReq, err := http.NewRequest(entry.RequestMethod, targetReqURL.String(), r.Body)
		if err != nil {
			log.Printf("%sERROR: Failed to create new request: %v%s", colorRed, err, colorReset)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		copyHeaders(r.Header, proxyReq.Header)
		proxyReq.Host = targetURLParsed.Host
		proxyReq.Header.Set("X-Forwarded-Host", entry.RequestHost)
		proxyReq.Header.Set("X-Forwarded-For", getClientIP(r))
		if r.TLS != nil {
			proxyReq.Header.Set("X-Forwarded-Proto", "https")
		} else {
			proxyReq.Header.Set("X-Forwarded-Proto", "http")
		}
		removeHopByHopHeaders(proxyReq.Header)

		client := http.DefaultClient
		resp, err := client.Do(proxyReq)
		if err != nil {
			log.Printf("%sERROR: Failed to reach target server %q: %v%s", colorRed, targetURL, err, colorReset)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()

		// --- Read Response Body ---
		var responseBodyBytes []byte
		if resp.Body != nil && resp.ContentLength != 0 {
			responseBodyBytes, err = io.ReadAll(resp.Body)
			if err != nil {
				log.Printf("%sERROR: Failed reading response body: %v%s", colorRed, err, colorReset)
			}
			entry.ResponseBody = responseBodyBytes
		}

		// --- Log Response Details ---
		entry.StatusCode = resp.StatusCode
		entry.ResponseHeaders = resp.Header.Clone()
		entry.Duration = time.Since(startTime)

		statusColor := colorGreen
		if entry.StatusCode >= 500 {
			statusColor = colorRed
		} else if entry.StatusCode >= 400 {
			statusColor = colorYellow
		}

		fmt.Printf("%s--- Target Response ----%s\n", colorBold+colorCyan, colorReset)
		fmt.Printf("%sStatus:%s %s%s (%d)%s\n",
			colorGray, colorReset,
			colorBold+statusColor, resp.Status, entry.StatusCode, colorReset,
		)
		printHeaders("Response Headers:", entry.ResponseHeaders)
		printBody("Response Body:", entry.ResponseHeaders.Get("Content-Type"), entry.ResponseBody)
		fmt.Printf("%sDuration:%s %v%s\n", colorGray, colorReset, entry.Duration) // Added Duration color reset
		fmt.Printf("%s-----------------------%s\n", colorBold+colorCyan, colorReset)

		// --- Send Response Back to Client ---
		copyHeaders(resp.Header, w.Header())
		removeHopByHopHeaders(w.Header())
		w.WriteHeader(resp.StatusCode)
		if len(responseBodyBytes) > 0 {
			_, err = w.Write(responseBodyBytes)
			if err != nil {
				log.Printf("%sWARN: Failed writing response body to client: %v%s", colorYellow, err, colorReset)
			}
		}
		fmt.Printf("%s=======================%s\n", colorBold+colorGray, colorReset)
	}

	// --- Start Server ---
	server := &http.Server{
		Addr:    listenAddr,
		Handler: http.HandlerFunc(proxyHandler),
	}
	log.Printf("INFO: Proxy server listening on %s%s%s", colorBold, listenAddr, colorReset)
	log.Printf("INFO: Forwarding requests to %s%s%s", colorBold, targetURL, colorReset)
	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("%sFATAL: Could not listen on %s: %v%s", colorRed, listenAddr, err, colorReset)
	}
	log.Println("INFO: Proxy server stopped")
}

// --- Helper Functions ---

func copyHeaders(src, dst http.Header) {
	for k, vv := range src {
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
}

func printHeaders(title string, h http.Header) {
	fmt.Printf("%s%s:%s\n", colorCyan, title, colorReset)
	headerCount := 0
	keys := make([]string, 0, len(h)); for k := range h { keys = append(keys, k) }; sort.Strings(keys)
	for _, k := range keys {
		vv := h[k]; lowerK := strings.ToLower(k)
		if _, exists := headersToOmit[lowerK]; exists { continue }
		headerCount++
		if strings.EqualFold(k, authorizationHeader) {
			var redactedValues []string
			for _, v := range vv {
				redacted := "[REDACTED SHORT]"
				if len(v) > 20 { redacted = fmt.Sprintf("%s...%s", v[:10], v[len(v)-10:]) } else if len(v) > 10 { redacted = fmt.Sprintf("%s...", v[:10]) }
				redactedValues = append(redactedValues, redacted)
			}
			fmt.Printf("  %s%s%s%s:%s %s%s%s\n", colorBold, colorWhite, k, colorReset, colorGray, colorRed, strings.Join(redactedValues, ", "), colorReset)
		} else {
			fmt.Printf("  %s%s%s%s:%s %s\n", colorBold, colorWhite, k, colorReset, colorGray, strings.Join(vv, ", "))
		}
	}
	if headerCount == 0 { fmt.Printf("  %s(No headers to display)%s\n", colorGray, colorReset) }
}

func printQueryParams(queryParams url.Values) {
	if len(queryParams) == 0 { return }
	fmt.Printf("%sQuery Parameters:%s\n", colorCyan, colorReset)
	keys := make([]string, 0, len(queryParams)); for k := range queryParams { keys = append(keys, k) }; sort.Strings(keys)
	for _, key := range keys {
		values := queryParams[key]
		fmt.Printf("  %s%s%s%s:%s %s%s%s\n", colorBold, colorBlue, key, colorReset, colorGray, colorWhite, strings.Join(values, ", "), colorReset)
	}
}

func printBody(title string, contentType string, body []byte) {
	fmt.Printf("%s%s:%s", colorCyan, title, colorReset)
	if len(body) == 0 { fmt.Printf(" %s(empty)%s\n", colorGray, colorReset); return }; fmt.Println()
	contentType = strings.TrimSpace(strings.Split(contentType, ";")[0])
	truncated := false; printData := body
	if len(body) > maxBodyPrintSize { printData = body[:maxBodyPrintSize]; truncated = true }
	formatted := false
	switch contentType {
	case "application/json":
		var v interface{}; decoder := json.NewDecoder(bytes.NewReader(printData)); decoder.UseNumber()
		if err := decoder.Decode(&v); err == nil { colorizeJSON(v, "  ", &formatted) }
	case "application/x-www-form-urlencoded":
		if values, err := url.ParseQuery(string(printData)); err == nil {
			keys := make([]string, 0, len(values)); for k := range values { keys = append(keys, k) }; sort.Strings(keys)
			for _, key := range keys { vals := values[key]; fmt.Printf("  %s%s%s%s:%s %s%s%s\n", colorBold, colorBlue, key, colorReset, colorGray, colorWhite, strings.Join(vals, ", "), colorReset) }
			formatted = true
		}
	}
	if !formatted { fmt.Printf("  %s```%s\n%s%s\n%s```%s\n", colorGray, colorReset, colorWhite, string(printData), colorGray, colorReset) }
	if truncated { fmt.Printf("  %s... (Body truncated at %d bytes)%s\n", colorRed, maxBodyPrintSize, colorReset) }
}

func colorizeJSON(data interface{}, indent string, formatted *bool) {
	switch v := data.(type) {
	case map[string]interface{}:
		if len(v) == 0 { fmt.Printf("%s{}%s\n", colorGray, colorReset); *formatted = true; return }
		fmt.Printf("%s{%s\n", colorGray, colorReset); *formatted = true
		keys := make([]string, 0, len(v)); for k := range v { keys = append(keys, k) }; sort.Strings(keys)
		for i, k := range keys {
			fmt.Printf("%s%s%s%s%s%s:%s ", indent, colorBold, colorBlue, k, colorReset, colorGray, colorReset)
			colorizeJSON(v[k], indent+"  ", formatted)
			if i < len(keys)-1 { fmt.Printf("%s,%s\n", colorGray, colorReset) } else { fmt.Println() }
		}
		fmt.Printf("%s%s}%s", indent[:len(indent)-2], colorGray, colorReset)
	case []interface{}:
		if len(v) == 0 { fmt.Printf("%s[]%s\n", colorGray, colorReset); *formatted = true; return }
		fmt.Printf("%s[%s\n", colorGray, colorReset); *formatted = true
		for i, item := range v {
			fmt.Print(indent); colorizeJSON(item, indent+"  ", formatted)
			if i < len(v)-1 { fmt.Printf("%s,%s\n", colorGray, colorReset) } else { fmt.Println() }
		}
		fmt.Printf("%s%s]%s", indent[:len(indent)-2], colorGray, colorReset)
	case string:
		escapedString := strconv.Quote(v); fmt.Printf("%s%s%s", colorWhite, escapedString, colorReset)
	case json.Number:
		fmt.Printf("%s%s%s", colorMagenta, v.String(), colorReset)
	case bool:
		fmt.Printf("%s%t%s", colorYellow, v, colorReset)
	case nil:
		fmt.Printf("%snull%s", colorGray, colorReset)
	default:
		fmt.Printf("%s%v%s", colorRed, v, colorReset); *formatted = false
	}
}

var hopHeaders = []string{ "Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate", "Proxy-Authorization", "Te", "Trailers", "Transfer-Encoding", "Upgrade", }
func removeHopByHopHeaders(header http.Header) { for _, h := range hopHeaders { header.Del(h) } }
func getClientIP(r *http.Request) string { ip := r.RemoteAddr; if colon := strings.LastIndex(ip, ":"); colon != -1 { if strings.Count(ip, ":") > 1 && strings.Contains(ip, "[") && strings.Contains(ip, "]") { ip = ip[1:strings.LastIndex(ip, "]")] } else { ip = ip[:colon] } }; return ip }
func singleJoiningSlash(a, b string) string { aslash := strings.HasSuffix(a, "/"); bslash := strings.HasPrefix(b, "/"); switch { case aslash && bslash: return a + b[1:]; case !aslash && !bslash: if b == "" || a == "/" { return a + b }; return a + "/" + b }; return a + b }

