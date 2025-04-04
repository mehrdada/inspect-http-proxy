package main

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/andybalholm/brotli" // Added for Brotli decompression
)

// Default values (can be overridden by flags)
const (
	defaultListenAddr = ":20003"
	defaultTargetURL  = "http://localhost:20004"
	// maxBodyPrintSize is now used conditionally based on the truncateLogBody flag
	maxBodyPrintSize = 1024 * 10 // Max size if truncation is enabled
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

// --- Configuration for Header Omission during Logging ---
var headersToOmit = map[string]struct{}{
	"x-forwarded-proto": {},
	"cf-ipcountry":      {},
	"cf-ray":            {},
	"x-real-ip":         {},
	// "accept-encoding":   {}, // Keep for request logging
	"cf-visitor":       {},
	"cf-connecting-ip": {},
	"cdn-loop":         {},
	"x-forwarded-for":  {},
	// Content-Encoding is important for response logging, don't omit
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
	ResponseBody    []byte // Original response body (potentially compressed, already de-chunked by http client)
	Duration        time.Duration
}

// --- Global variables to hold flag values ---
var (
	listenAddr      string
	targetURL       string
	truncateLogBody bool // New flag variable
)

func main() {
	// --- Define command-line flags ---
	flag.StringVar(&listenAddr, "listen", defaultListenAddr, "Address and port for the proxy to listen on")
	flag.StringVar(&targetURL, "target", defaultTargetURL, "URL of the target server to forward requests to")
	flag.BoolVar(&truncateLogBody, "truncate-log-body", false, fmt.Sprintf("Truncate logged body output to %d bytes", maxBodyPrintSize)) // New flag definition
	flag.Parse()                                                                                                                         // Parse the flags from the command line

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
			RequestHeaders: r.Header.Clone(), // Clone headers early
		}

		// --- Read Request Body ---
		var requestBodyBytes []byte
		if r.Body != nil && r.Body != http.NoBody {
			maxBytes := int64(10 * 1024 * 1024) // Limit actual request body size (e.g., 10MB) - separate from logging truncation
			r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			requestBodyBytes, err = io.ReadAll(r.Body)
			if err != nil {
				if err.Error() == "http: request body too large" {
					log.Printf("%sERROR: Request body exceeds limit: %v%s", colorRed, err, colorReset)
					http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
					return
				} else if err != io.EOF { // EOF is often expected, especially with empty or chunked bodies
					log.Printf("%sERROR: Failed reading request body: %v%s", colorRed, err, colorReset)
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
					return
				}
			}
			// Close the original body reader if it exists and is a closer
			if rc, ok := r.Body.(io.ReadCloser); ok {
				rc.Close()
			}
			// Restore the body so it can be read by the proxy request
			r.Body = io.NopCloser(bytes.NewBuffer(requestBodyBytes))
			entry.RequestBody = requestBodyBytes
		} else {
			r.Body = nil // Ensure nil body if none exists, important for http.NewRequest
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
		printBody("Request Body:", entry.RequestHeaders, entry.RequestBody) // Log request body
		fmt.Printf("%s------------------------%s\n", colorBold+colorCyan, colorReset)

		// --- Prepare & Send Forwarded Request ---
		targetReqURL := *targetURLParsed
		targetReqURL.Path = singleJoiningSlash(targetURLParsed.Path, entry.RequestURL.Path)
		targetReqURL.RawQuery = entry.RequestURL.RawQuery // Preserve original query string

		// Create request using the potentially restored r.Body
		proxyReq, err := http.NewRequest(entry.RequestMethod, targetReqURL.String(), r.Body)
		if err != nil {
			log.Printf("%sERROR: Failed to create new request: %v%s", colorRed, err, colorReset)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		copyHeaders(entry.RequestHeaders, proxyReq.Header) // Copy headers from original request
		proxyReq.Host = targetURLParsed.Host               // Set Host header correctly for target
		// Add X-Forwarded-* headers
		proxyReq.Header.Set("X-Forwarded-Host", entry.RequestHost)
		proxyReq.Header.Set("X-Forwarded-For", getClientIP(r))
		if r.TLS != nil {
			proxyReq.Header.Set("X-Forwarded-Proto", "https")
		} else {
			proxyReq.Header.Set("X-Forwarded-Proto", "http")
		}

		removeHopByHopHeaders(proxyReq.Header) // Remove hop-by-hop before sending

		// Configure HTTP client transport
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.DisableCompression = true // Keep response compressed for forwarding to client
		client := &http.Client{Transport: transport}

		// --- Send Request to Target ---
		resp, err := client.Do(proxyReq)
		if err != nil {
			log.Printf("%sERROR: Failed to reach target server %q: %v%s", colorRed, targetURL, err, colorReset)
			if urlErr, ok := err.(*url.Error); ok {
				if _, ok := urlErr.Err.(*net.OpError); ok {
					http.Error(w, "Bad Gateway", http.StatusBadGateway)
					return
				}
			}
			http.Error(w, "Internal Server Error", http.StatusInternalServerError) // Default error
			return
		}
		defer resp.Body.Close()

		// --- Read Response Body ---
		// io.ReadAll handles de-chunking automatically. responseBodyBytes contains the complete logical body.
		var responseBodyBytes []byte
		if resp.Body != nil {
			responseBodyBytes, err = io.ReadAll(resp.Body)
			if err != nil {
				// Log error but proceed, as we might still have headers/status
				log.Printf("%sWARN: Error reading full response body (might be incomplete): %v%s", colorYellow, err, colorReset)
			}
			entry.ResponseBody = responseBodyBytes // Store the ORIGINAL (potentially compressed) bytes
		}

		// --- Log Response Details ---
		entry.StatusCode = resp.StatusCode
		entry.ResponseHeaders = resp.Header.Clone() // Clone headers received from target
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
		// Log the body: printBody will attempt decompression *for logging only*.
		// It now respects the truncateLogBody flag.
		printBody("Response Body:", entry.ResponseHeaders, entry.ResponseBody) // Log response body
		fmt.Printf("%sDuration:%s %v%s\n", colorGray, colorReset, entry.Duration, colorReset)
		fmt.Printf("%s-----------------------%s\n", colorBold+colorCyan, colorReset)

		// --- Send Response Back to Client ---
		destHeaders := w.Header()
		copyHeaders(entry.ResponseHeaders, destHeaders) // Copy original headers
		removeHopByHopHeaders(destHeaders)              // Remove hop-by-hop for client connection

		w.WriteHeader(resp.StatusCode) // Write status code

		// Write the original response body bytes (potentially compressed)
		if len(responseBodyBytes) > 0 {
			_, err = w.Write(responseBodyBytes)
			if err != nil {
				// Error writing body (e.g., client closed connection)
				log.Printf("%sWARN: Failed writing response body to client: %v%s", colorYellow, err, colorReset)
			}
		}
		fmt.Printf("%s=======================%s\n", colorBold+colorGray, colorReset)
	}

	// --- Start Server ---
	server := &http.Server{
		Addr:    listenAddr,
		Handler: http.HandlerFunc(proxyHandler),
		// Add basic timeouts for robustness
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}
	log.Printf("INFO: Proxy server listening on %s%s%s", colorBold, listenAddr, colorReset)
	log.Printf("INFO: Forwarding requests to %s%s%s", colorBold, targetURL, colorReset)
	if truncateLogBody {
		log.Printf("INFO: Logged body output will be truncated to %d bytes.", maxBodyPrintSize)
	} else {
		log.Printf("INFO: Logged body output will not be truncated.")
	}
	err = server.ListenAndServe()
	if err != nil && err != http.ErrServerClosed {
		log.Fatalf("%sFATAL: Could not listen on %s: %v%s", colorRed, listenAddr, err, colorReset)
	}
	log.Println("INFO: Proxy server stopped")
}

// --- Helper Functions ---

// copyHeaders performs a deep copy of headers from src to dst.
func copyHeaders(src, dst http.Header) {
	for k, vv := range src {
		dst[k] = append([]string(nil), vv...) // Create a fresh copy of the slice
	}
}

// printHeaders prints headers to the console with formatting and redaction.
func printHeaders(title string, h http.Header) {
	fmt.Printf("%s%s:%s\n", colorCyan, title, colorReset)
	headerCount := 0
	keys := make([]string, 0, len(h))
	for k := range h {
		keys = append(keys, k)
	}
	sort.Strings(keys) // Sort for consistent output
	for _, k := range keys {
		vv := h[k]
		lowerK := strings.ToLower(k)
		// Check if this header should be omitted from logging
		if _, exists := headersToOmit[lowerK]; exists {
			continue
		}

		headerCount++
		// Redact Authorization header for security
		if strings.EqualFold(k, authorizationHeader) {
			var redactedValues []string
			for _, v := range vv {
				redacted := "[REDACTED SHORT]"
				if len(v) > 20 {
					redacted = fmt.Sprintf("%s...%s", v[:10], v[len(v)-10:])
				} else if len(v) > 10 {
					redacted = fmt.Sprintf("%s...", v[:10])
				} else if len(v) > 0 {
					redacted = "[REDACTED]"
				}
				redactedValues = append(redactedValues, redacted)
			}
			fmt.Printf("  %s%s%s%s:%s %s%s%s\n", colorBold, colorWhite, k, colorReset, colorGray, colorRed, strings.Join(redactedValues, ", "), colorReset)
		} else {
			fmt.Printf("  %s%s%s%s:%s %s\n", colorBold, colorWhite, k, colorReset, colorGray, strings.Join(vv, ", "))
		}
	}
	if headerCount == 0 {
		fmt.Printf("  %s(No headers to display)%s\n", colorGray, colorReset)
	}
}

// printQueryParams prints query parameters with formatting.
func printQueryParams(queryParams url.Values) {
	if len(queryParams) == 0 {
		return
	}
	fmt.Printf("%sQuery Parameters:%s\n", colorCyan, colorReset)
	keys := make([]string, 0, len(queryParams))
	for k := range queryParams {
		keys = append(keys, k)
	}
	sort.Strings(keys) // Sort for consistent output
	for _, key := range keys {
		values := queryParams[key]
		fmt.Printf("  %s%s%s%s:%s %s%s%s\n", colorBold, colorBlue, key, colorReset, colorGray, colorWhite, strings.Join(values, ", "), colorReset)
	}
}

// printBody attempts to decompress (if applicable), format, and print the body for logging.
// Respects the truncateLogBody flag to limit the final output string length.
func printBody(title string, headers http.Header, originalCompleteBody []byte) {
	fmt.Printf("%s%s:%s", colorCyan, title, colorReset)
	if len(originalCompleteBody) == 0 {
		fmt.Printf(" %s(empty)%s\n", colorGray, colorReset)
		return
	}

	bodyToProcess := originalCompleteBody // Start with the complete body (already de-chunked)
	decompressed := false
	encoding := headers.Get("Content-Encoding")
	encoding = strings.ToLower(strings.TrimSpace(encoding))

	var decompErr error
	if encoding != "" && len(originalCompleteBody) > 0 {
		bodyReader := bytes.NewReader(originalCompleteBody)
		var reader io.Reader = bodyReader
		switch encoding {
		case "gzip":
			gzipReader, err := gzip.NewReader(bodyReader)
			if err == nil {
				defer gzipReader.Close()
				reader = gzipReader
			} else {
				decompErr = fmt.Errorf("gzip reader init failed: %w", err)
			}
		case "br":
			reader = brotli.NewReader(bodyReader)
		case "deflate":
			flateReader := flate.NewReader(bodyReader)
			defer flateReader.Close()
			reader = flateReader
		default:
			reader = nil
			decompErr = fmt.Errorf("unsupported encoding for logging: %s", encoding)
		}

		if reader != bodyReader && decompErr == nil {
			var decompressedBuf bytes.Buffer
			_, err := io.Copy(&decompressedBuf, reader) // Read the full decompressed body
			if err == nil {
				bodyToProcess = decompressedBuf.Bytes() // Use decompressed data for processing
				decompressed = true
			} else {
				decompErr = fmt.Errorf("decompression read failed (%s): %w", encoding, err)
				// Fallback: bodyToProcess remains originalCompleteBody
			}
		}
	}

	// Print status about decompression attempt
	if encoding != "" {
		if decompressed {
			fmt.Printf(" %s(decoded from %s for printing)%s\n", colorGray, encoding, colorReset)
		} else if decompErr != nil {
			fmt.Printf(" %s(decoding %s failed: %v - showing original)%s\n", colorRed, encoding, decompErr, colorReset)
		} else {
			fmt.Printf(" %s(encoding '%s' present but not decoded for printing)%s\n", colorGray, encoding, colorReset)
		}
	} else {
		fmt.Println() // Start body on new line if no encoding info
	}

	contentType := headers.Get("Content-Type")
	baseContentType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	originalLength := len(bodyToProcess) // Length of the data we're about to format/print

	var outputString string
	formatted := false

	switch baseContentType {
	case "application/json":
		var v interface{}
		// Attempt to decode the *entire* bodyToProcess
		decoder := json.NewDecoder(bytes.NewReader(bodyToProcess))
		decoder.UseNumber()
		err := decoder.Decode(&v)
		if err == nil && v != nil {
			var sb strings.Builder
			if err := formatJSONToStringBuilder(&sb, v, "  "); err == nil {
				outputString = sb.String()
				formatted = true
			} else {
				log.Printf("%sDEBUG: JSON formatting to string failed: %v%s", colorYellow, err, colorReset)
				formatted = false
			}
		} else {
			formatted = false
			if err != nil {
				log.Printf("%sDEBUG: JSON decoding failed: %v%s", colorYellow, err, colorReset)
			}
		}

	case "application/x-www-form-urlencoded":
		if values, err := url.ParseQuery(string(bodyToProcess)); err == nil && len(values) > 0 {
			var sb strings.Builder
			keys := make([]string, 0, len(values))
			for k := range values {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for i, key := range keys {
				if i > 0 {
					sb.WriteString("\n")
				}
				vals := values[key]
				sb.WriteString(fmt.Sprintf("  %s%s%s%s:%s %s%s%s", colorBold, colorBlue, key, colorReset, colorGray, colorWhite, strings.Join(vals, ", "), colorReset))
			}
			outputString = sb.String()
			formatted = true
		} else {
			formatted = false
		}
	}

	// Handle raw text or fallback cases
	if !formatted {
		if isPrintableContentType(baseContentType) || (baseContentType == "" && looksLikePrintableText(bodyToProcess)) {
			var sb strings.Builder
			sb.WriteString(fmt.Sprintf("  %s```%s\n", colorGray, colorReset))
			// Use bodyToProcess (potentially decompressed) for raw output
			sb.WriteString(fmt.Sprintf("%s%s%s", colorWhite, string(bodyToProcess), colorReset))
			sb.WriteString(fmt.Sprintf("\n%s```%s", colorGray, colorReset))
			outputString = sb.String()
		} else {
			outputString = fmt.Sprintf("  %s[Content type '%s' (%d bytes), not displayed as text]%s", colorGray, baseContentType, originalLength, colorReset)
		}
	}

	// Apply truncation based on the flag *after* formatting
	displayString := outputString
	outputTruncated := false // Flag specifically for output truncation message

	if truncateLogBody && len(outputString) > maxBodyPrintSize {
		// Truncate the final output string representation
		limit := maxBodyPrintSize
		// Simple string truncation for console output
		displayString = outputString[:limit]
		outputTruncated = true
	}

	// Print the final (potentially truncated) string
	fmt.Println(displayString) // Print the result which includes newlines if formatted

	// Print the truncation message only if the output string was truncated
	if outputTruncated {
		fmt.Printf("  %s... (Output truncated for display, original data size %d bytes)%s\n", colorRed, originalLength, colorReset)
	}
}

// formatJSONToStringBuilder recursively formats JSON data into a strings.Builder
func formatJSONToStringBuilder(sb *strings.Builder, data interface{}, indent string) error {
	switch v := data.(type) {
	case map[string]interface{}:
		if len(v) == 0 {
			sb.WriteString(fmt.Sprintf("%s{}%s", colorGray, colorReset))
			return nil
		}
		sb.WriteString(fmt.Sprintf("%s{%s", colorGray, colorReset))
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		first := true
		for _, k := range keys {
			if !first {
				sb.WriteString(fmt.Sprintf("%s,%s", colorGray, colorReset))
			}
			sb.WriteString(fmt.Sprintf("\n%s%s%s%s%s%s:%s ", indent, colorBold, colorBlue, k, colorReset, colorGray, colorReset))
			if err := formatJSONToStringBuilder(sb, v[k], indent+"  "); err != nil {
				return err
			}
			first = false
		}
		sb.WriteString(fmt.Sprintf("\n%s%s}%s", indent[:len(indent)-2], colorGray, colorReset))
	case []interface{}:
		if len(v) == 0 {
			sb.WriteString(fmt.Sprintf("%s[]%s", colorGray, colorReset))
			return nil
		}
		sb.WriteString(fmt.Sprintf("%s[%s", colorGray, colorReset))
		first := true
		for _, item := range v {
			if !first {
				sb.WriteString(fmt.Sprintf("%s,%s", colorGray, colorReset))
			}
			sb.WriteString(fmt.Sprintf("\n%s", indent))
			if err := formatJSONToStringBuilder(sb, item, indent+"  "); err != nil {
				return err
			}
			first = false
		}
		sb.WriteString(fmt.Sprintf("\n%s%s]%s", indent[:len(indent)-2], colorGray, colorReset))
	case string:
		escapedString := strconv.Quote(v)
		sb.WriteString(fmt.Sprintf("%s%s%s", colorGreen, escapedString, colorReset))
	case json.Number:
		sb.WriteString(fmt.Sprintf("%s%s%s", colorMagenta, v.String(), colorReset))
	case bool:
		sb.WriteString(fmt.Sprintf("%s%t%s", colorYellow, v, colorReset))
	case nil:
		sb.WriteString(fmt.Sprintf("%snull%s", colorGray, colorReset))
	default:
		sb.WriteString(fmt.Sprintf("%s(Unknown JSON type: %T)%v%s", colorRed, v, v, colorReset))
	}
	return nil
}

// isPrintableContentType checks if a MIME type is likely to contain printable text.
func isPrintableContentType(contentType string) bool {
	contentType = strings.ToLower(contentType)
	return strings.HasPrefix(contentType, "text/") ||
		strings.Contains(contentType, "json") ||
		strings.Contains(contentType, "xml") ||
		strings.Contains(contentType, "javascript") ||
		strings.Contains(contentType, "yaml") ||
		strings.Contains(contentType, "toml") ||
		contentType == "application/x-www-form-urlencoded"
}

// looksLikePrintableText checks if a byte slice seems to be mostly printable UTF-8 characters.
func looksLikePrintableText(data []byte) bool {
	if len(data) == 0 {
		return true
	}
	checkLen := 1024
	if len(data) < checkLen {
		checkLen = len(data)
	}
	sample := data[:checkLen]
	controlChars := 0
	totalChars := 0
	for i := 0; i < len(sample); {
		r, size := utf8.DecodeRune(sample[i:])
		totalChars++
		if r == utf8.RuneError && size == 1 {
			return false // Invalid UTF-8
		}
		if !unicode.IsPrint(r) && r != '\n' && r != '\t' && r != '\r' {
			controlChars++
		}
		i += size
	}
	if totalChars == 0 {
		return true
	}
	// Allow a small fraction of control characters (e.g., less than 10%)
	return float64(controlChars)/float64(totalChars) < 0.1
}

// Hop-by-hop headers that should not be forwarded between connections.
var hopHeaders = []string{
	"Connection",
	"Proxy-Connection", // Non-standard but seen
	"Keep-Alive",
	"Proxy-Authenticate",
	"Proxy-Authorization",
	"Te", // Trailers encoding
	"Trailers",
	"Transfer-Encoding", // Chunking, etc. Handled by http libraries implicitly.
	"Upgrade",           // For protocol switching like WebSockets
}

// removeHopByHopHeaders removes headers defined in hopHeaders and any listed in the Connection header.
func removeHopByHopHeaders(header http.Header) {
	connectionHeaders := []string{}
	if connHdrs := header.Get("Connection"); connHdrs != "" {
		for _, h := range strings.Split(connHdrs, ",") {
			connectionHeaders = append(connectionHeaders, strings.TrimSpace(http.CanonicalHeaderKey(h)))
		}
	}

	// Remove standard hop-by-hop headers
	for _, h := range hopHeaders {
		header.Del(h)
	}

	// Remove headers listed in the Connection header value
	for _, h := range connectionHeaders {
		header.Del(h)
	}
}

// getClientIP extracts the client IP address from request headers or RemoteAddr.
func getClientIP(r *http.Request) string {
	// Check common headers used by proxies/load balancers first
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		ips := strings.Split(fwd, ",")
		clientIP := strings.TrimSpace(ips[0]) // First IP is usually the original client
		if clientIP != "" {
			return clientIP
		}
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	// Fallback to RemoteAddr (IP:port)
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return ip // Successfully split IP and port
	}
	// If SplitHostPort fails (e.g., just an IP, unusual), return RemoteAddr as is
	return r.RemoteAddr
}

// singleJoiningSlash ensures exactly one slash joins two path components.
func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:] // "a/" + "/b" -> "a/b"
	case !aslash && !bslash:
		if b == "" { // "a" + "" -> "a"
			return a
		}
		if a == "" { // "" + "b" -> "/b" or "b" depending if b is absolute
			if strings.HasPrefix(b, "/") {
				return b
			}
			return "/" + b // Prepend slash if b is relative and a is empty
		}
		return a + "/" + b // "a" + "b" -> "a/b"
	default: // One has slash, one doesn't
		return a + b // "a/" + "b" -> "a/b" OR "a" + "/b" -> "a/b"
	}
}
