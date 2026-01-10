package main

import (
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// --- Configuration & Constants ---

const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPink   = "\033[1;35m" // Bold Pink/Magenta
	ColorBold   = "\033[1m"
)

var (
	targetURL   string
	proxyURL    string
	headersRaw  string
	concurrency int
	force       bool
	verbose     bool
	client      *http.Client
	headerMap   map[string]string
)

// --- Structs ---

type Result struct {
	Name        string
	Vulnerable  bool
	Severity    string // LOW, MEDIUM, HIGH, INFO
	Description string
	Payload     string
}

type CheckFunc func(string) Result

// --- Main Execution ---

func main() {
	// 1. Banner
	printBanner()

	// 2. Flag Parsing
	flag.StringVar(&targetURL, "t", "", "Target URL (e.g., https://example.com/graphql)")
	flag.StringVar(&proxyURL, "x", "", "Proxy URL (http://127.0.0.1:8080)")
	flag.StringVar(&headersRaw, "H", "", "Custom Headers (Key:Value,Key:Value)")
	flag.IntVar(&concurrency, "c", 10, "Concurrency level")
	flag.BoolVar(&force, "f", false, "Force scan even if GraphQL detection fails")
	flag.BoolVar(&verbose, "v", false, "Verbose output")
	flag.Parse()

	if targetURL == "" {
		fmt.Printf("%s[-] Target URL is required. Use -t <url>%s\n", ColorRed, ColorReset)
		os.Exit(1)
	}

	// 3. Setup HTTP Client
	setupClient()

	// 4. Detection Phase
	if !force {
		fmt.Printf("%s[*] Detecting GraphQL at %s...%s\n", ColorBlue, targetURL, ColorReset)
		if !detectGraphQL(targetURL) {
			fmt.Printf("%s[-] GraphQL not detected. Use -f to force scan.%s\n", ColorRed, ColorReset)
			os.Exit(1)
		}
		fmt.Printf("%s[+] GraphQL Confirmed!%s\n", ColorGreen, ColorReset)
	}

	// 5. Register Checks
	checks := []CheckFunc{
		CheckIntrospection,
		CheckGraphiQL,
		CheckAliasOverloading,
		CheckBatchQuery,
		CheckDirectiveOverloading,
		CheckFieldDuplication,
		CheckCircularIntrospection,
		CheckCSRF_GET,
		CheckMutationOverGET,
		CheckCSRF_POST_UrlEncoded,
		CheckCSRF_POST_TextPlain,
		CheckTracing,
		CheckFieldSuggestions,
		CheckDebugMode,
		CheckMethodNotAllowed,
		CheckDeepNesting,
		CheckErrorVerbosity,
		CheckEmptyArrayPanic,
		CheckInterfaceDiscovery,
		CheckPlaygroundExposure,
		CheckMalformJSON,
	}

	fmt.Printf("%s[*] Starting scan with %d checks (Strict Mode)...%s\n\n", ColorBlue, len(checks), ColorReset)

	// 6. Worker Pool & Execution
	results := make(chan Result, len(checks))
	var wg sync.WaitGroup

	// Channel to distribute work
	jobChan := make(chan CheckFunc, len(checks))

	// Start Workers
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for check := range jobChan {
				results <- check(targetURL)
			}
		}()
	}

	// Send Jobs
	for _, c := range checks {
		jobChan <- c
	}
	close(jobChan)

	// Wait for workers in a separate goroutine to close results channel
	go func() {
		wg.Wait()
		close(results)
	}()

	// 7. Output Handling
	for res := range results {
		if res.Vulnerable {
			color := ColorRed
			if res.Severity == "INFO" { color = ColorBlue }
			if res.Severity == "LOW" { color = ColorYellow }

			fmt.Printf("%s[VULN] [%s] %s%s\n", color, res.Severity, res.Name, ColorReset)
			fmt.Printf("       %s\n", res.Description)
			if verbose {
				fmt.Printf("       Payload: %s\n", res.Payload)
			}
		} else if verbose {
			fmt.Printf("%s[SAFE] %s%s\n", ColorGreen, res.Name, ColorReset)
		}
	}
	
	fmt.Println("\n[*] Scan Complete.")
}

// --- Helper Functions ---

func printBanner() {
	banner := `
   _____                 _     ____  _       
  / ____|               | |   / __ \| |      
 | |  __ _ __ __ _ _ __ | |__| |  | | |      
 | | |_ | '__/ _' | '_ \| '_ \ |  | | |      
 | |__| | | | (_| | |_) | | | |__| | |____   
  \_____|_|  \__,_| .__/|_| |_|\___\______|  
                  | |                        
                  |_|   
`
	fmt.Printf("%s%s%s", ColorPink, banner, ColorReset)
	fmt.Printf("%s    GraphQLSuite by SpiderSec (v2.2 Strict)%s\n\n", ColorPink, ColorReset)
}

func setupClient() {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err == nil {
			transport.Proxy = http.ProxyURL(u)
		}
	}

	client = &http.Client{
		Transport: transport,
		Timeout:   15 * time.Second,
	}

	// Parse Headers
	headerMap = make(map[string]string)
	if headersRaw != "" {
		parts := strings.Split(headersRaw, ",")
		for _, p := range parts {
			kv := strings.SplitN(p, ":", 2)
			if len(kv) == 2 {
				headerMap[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1])
			}
		}
	}
}

func sendRequest(method, urlStr, contentType string, body io.Reader) (*http.Response, string, error) {
	req, err := http.NewRequest(method, urlStr, body)
	if err != nil {
		return nil, "", err
	}

	// Default Headers
	req.Header.Set("User-Agent", "GraphQLSuite/2.2 (SpiderSec)")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	// Custom Headers
	for k, v := range headerMap {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	return resp, string(respBody), nil
}

func detectGraphQL(urlStr string) bool {
	payload := `{"query":"query { __typename }"}`
	resp, body, err := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	if err != nil {
		return false
	}
	return resp.StatusCode == 200 && strings.Contains(body, "__typename")
}

// isSuccessfulGraphQL checks if the response is a valid execution.
// It returns TRUE if "data" is present AND "errors" is missing.
func isSuccessfulGraphQL(body string) bool {
	return strings.Contains(body, `"data"`) && !strings.Contains(body, `"errors"`) && !strings.Contains(body, "<html")
}

// --- VULNERABILITY CHECKS ---

// 1. Introspection
func CheckIntrospection(urlStr string) Result {
	payload := `{"query":"query { __schema { queryType { name } } }"}`
	_, body, err := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	
	if err == nil && strings.Contains(body, "__schema") && !strings.Contains(body, "Schema is disabled") {
		return Result{Name: "Introspection Enabled", Vulnerable: true, Severity: "LOW", Description: "Full schema discovery possible.", Payload: payload}
	}
	return Result{Name: "Introspection Enabled", Vulnerable: false}
}

// 2. Alias Overloading (DoS)
func CheckAliasOverloading(urlStr string) Result {
	var b strings.Builder
	b.WriteString("query {")
	for i := 0; i < 150; i++ {
		b.WriteString(fmt.Sprintf("alias%d: __typename ", i))
	}
	b.WriteString("}")
	payload := fmt.Sprintf(`{"query":"%s"}`, b.String())

	start := time.Now()
	resp, body, err := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	duration := time.Since(start)

	// Must be slow (>2s) AND Successful (no errors)
	if err == nil && resp.StatusCode == 200 && duration > 2*time.Second && isSuccessfulGraphQL(body) {
		return Result{Name: "Alias Overloading (DoS)", Vulnerable: true, Severity: "HIGH", Description: "Server processed 150+ aliases, causing delay.", Payload: "Big Alias Query"}
	}
	return Result{Name: "Alias Overloading (DoS)", Vulnerable: false}
}

// 3. Batch Queries (DoS)
func CheckBatchQuery(urlStr string) Result {
	payload := "[" + strings.Repeat(`{"query":"query { __typename }"},`, 10)
	payload = strings.TrimSuffix(payload, ",") + "]"

	_, body, err := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	
	// Must return a JSON Array (which implies it executed all of them)
	if err == nil && strings.HasPrefix(strings.TrimSpace(body), "[") {
		return Result{Name: "Batch Queries", Vulnerable: true, Severity: "HIGH", Description: "Batching enabled. Can be used for DoS or Brute Force.", Payload: payload}
	}
	return Result{Name: "Batch Queries", Vulnerable: false}
}

// 4. Directive Overloading (DoS)
func CheckDirectiveOverloading(urlStr string) Result {
	directives := strings.Repeat("@skip(if: false) ", 100)
	payload := fmt.Sprintf(`{"query":"query { __typename %s }"}`, directives)

	resp, body, err := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	
	// Vulnerable only if server executes it without error
	if err == nil && resp.StatusCode == 200 && isSuccessfulGraphQL(body) {
		return Result{Name: "Directive Overloading", Vulnerable: true, Severity: "MEDIUM", Description: "Server accepts high number of directives without error.", Payload: payload}
	}
	return Result{Name: "Directive Overloading", Vulnerable: false}
}

// 5. Field Duplication (DoS)
func CheckFieldDuplication(urlStr string) Result {
	fields := strings.Repeat("__typename ", 500)
	payload := fmt.Sprintf(`{"query":"query { %s }"}`, fields)

	start := time.Now()
	resp, body, err := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	duration := time.Since(start)

	// Vulnerable only if it took time AND executed (didn't return "Duplicate field" error)
	if err == nil && resp.StatusCode == 200 && duration > 1*time.Second && isSuccessfulGraphQL(body) {
		return Result{Name: "Field Duplication", Vulnerable: true, Severity: "MEDIUM", Description: "Server processed 500 duplicate fields.", Payload: "Repeated __typename"}
	}
	return Result{Name: "Field Duplication", Vulnerable: false}
}

// 6. Circular Introspection (DoS)
func CheckCircularIntrospection(urlStr string) Result {
	// A query that forces recursive type lookup
	q := `query { __schema { types { fields { type { fields { type { fields { type { name } } } } } } } } }`
	payload := fmt.Sprintf(`{"query":"%s"}`, q)
	
	resp, body, err := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	
	// Vulnerable ONLY if it returns "data" and NO "errors" (meaning depth check failed)
	if err == nil && resp.StatusCode == 200 && isSuccessfulGraphQL(body) {
		return Result{Name: "Circular Introspection", Vulnerable: true, Severity: "HIGH", Description: "Deeply nested introspection executed without error.", Payload: q}
	}
	return Result{Name: "Circular Introspection", Vulnerable: false}
}

// 7. CSRF via GET
func CheckCSRF_GET(urlStr string) Result {
	u, _ := url.Parse(urlStr)
	q := u.Query()
	q.Set("query", "query { __typename }")
	u.RawQuery = q.Encode()

	resp, body, err := sendRequest("GET", u.String(), "", nil)
	
	// Vulnerable only if it returns GraphQL DATA via GET
	if err == nil && resp.StatusCode == 200 && isSuccessfulGraphQL(body) {
		return Result{Name: "CSRF (GET Based)", Vulnerable: true, Severity: "MEDIUM", Description: "API accepts queries via GET, vulnerable to CSRF.", Payload: u.String()}
	}
	return Result{Name: "CSRF (GET Based)", Vulnerable: false}
}

// 8. Mutation via GET (High CSRF risk)
func CheckMutationOverGET(urlStr string) Result {
	u, _ := url.Parse(urlStr)
	q := u.Query()
	// Using a harmless mutation attempts
	q.Set("query", "mutation { __typename }") 
	u.RawQuery = q.Encode()

	resp, body, err := sendRequest("GET", u.String(), "", nil)
	
	// Vulnerable only if it executes (returns data)
	// If it returns "Mutation not allowed in GET", it is safe.
	if err == nil && resp.StatusCode == 200 && isSuccessfulGraphQL(body) {
		return Result{Name: "Mutation over GET", Vulnerable: true, Severity: "HIGH", Description: "API processed 'mutation' keyword via GET.", Payload: u.String()}
	}
	return Result{Name: "Mutation over GET", Vulnerable: false}
}

// 9. CSRF via POST UrlEncoded
func CheckCSRF_POST_UrlEncoded(urlStr string) Result {
	data := url.Values{}
	data.Set("query", "query { __typename }")
	
	resp, body, err := sendRequest("POST", urlStr, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	
	if err == nil && resp.StatusCode == 200 && isSuccessfulGraphQL(body) {
		return Result{Name: "CSRF (POST UrlEncoded)", Vulnerable: true, Severity: "MEDIUM", Description: "API accepts x-www-form-urlencoded.", Payload: data.Encode()}
	}
	return Result{Name: "CSRF (POST UrlEncoded)", Vulnerable: false}
}

// 10. CSRF via Text/Plain (Bypass Preflight)
func CheckCSRF_POST_TextPlain(urlStr string) Result {
	payload := `{"query":"query { __typename }"}`
	resp, body, err := sendRequest("POST", urlStr, "text/plain", bytes.NewBufferString(payload))
	
	if err == nil && resp.StatusCode == 200 && isSuccessfulGraphQL(body) {
		return Result{Name: "CSRF (Text/Plain)", Vulnerable: true, Severity: "HIGH", Description: "API accepts text/plain Content-Type.", Payload: payload}
	}
	return Result{Name: "CSRF (Text/Plain)", Vulnerable: false}
}

// 11. Tracing
func CheckTracing(urlStr string) Result {
	payload := `{"query":"query { __typename }", "extensions": {"tracing": true}}`
	_, body, err := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))

	if err == nil && strings.Contains(body, "\"tracing\":") && strings.Contains(body, "duration") {
		return Result{Name: "GraphQL Tracing", Vulnerable: true, Severity: "INFO", Description: "Performance tracing exposed.", Payload: payload}
	}
	return Result{Name: "GraphQL Tracing", Vulnerable: false}
}

// 12. Field Suggestions
func CheckFieldSuggestions(urlStr string) Result {
	payload := `{"query":"query { __typenam }"}` // Typo
	_, body, err := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))

	if err == nil && strings.Contains(body, "Did you mean") {
		return Result{Name: "Field Suggestions", Vulnerable: true, Severity: "INFO", Description: "Server suggests fields on typo.", Payload: payload}
	}
	return Result{Name: "Field Suggestions", Vulnerable: false}
}

// 13. GraphiQL Discovery
func CheckGraphiQL(urlStr string) Result {
	u, _ := url.Parse(urlStr)
	base := u.Scheme + "://" + u.Host
	paths := []string{"/graphiql", "/graphql/console", "/playground", "/explorer"}
	
	for _, p := range paths {
		resp, _, _ := sendRequest("GET", base+p, "", nil)
		if resp != nil && resp.StatusCode == 200 {
			return Result{Name: "GraphiQL/Playground", Vulnerable: true, Severity: "LOW", Description: "GraphiQL interface found at " + p, Payload: base + p}
		}
	}
	return Result{Name: "GraphiQL/Playground", Vulnerable: false}
}

// 14. Debug Mode
func CheckDebugMode(urlStr string) Result {
	payload := `{"query":"query { error_trigger }"}`
	_, body, err := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))

	if err == nil && (strings.Contains(body, "stackTrace") || strings.Contains(body, "debugMessage")) {
		return Result{Name: "Debug Mode / Verbose Errors", Vulnerable: true, Severity: "LOW", Description: "Stack trace or debug info leaked.", Payload: payload}
	}
	return Result{Name: "Debug Mode", Vulnerable: false}
}

// 15. Method Not Allowed (Bypass)
func CheckMethodNotAllowed(urlStr string) Result {
	payload := `{"query":"query { __typename }"}`
	for _, method := range []string{"PUT", "DELETE"} {
		resp, body, _ := sendRequest(method, urlStr, "application/json", bytes.NewBufferString(payload))
		if resp != nil && resp.StatusCode == 200 && isSuccessfulGraphQL(body) {
			return Result{Name: "HTTP Method Override", Vulnerable: true, Severity: "LOW", Description: method + " request executed query.", Payload: method}
		}
	}
	return Result{Name: "HTTP Method Override", Vulnerable: false}
}

// 16. Deep Nesting (DoS)
func CheckDeepNesting(urlStr string) Result {
	nest := strings.Repeat("{a", 50) + strings.Repeat("}", 50)
	payload := fmt.Sprintf(`{"query":"query %s"}`, nest)
	
	resp, body, err := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	// Vulnerable only if execution proceeds (server tries to resolve 'a' at depth 50)
	// If response contains "Max depth exceeded", it's safe.
	if err == nil && resp.StatusCode == 200 {
		if strings.Contains(body, "Cannot query field") && !strings.Contains(body, "depth") {
			return Result{Name: "Deep Nesting allowed", Vulnerable: true, Severity: "MEDIUM", Description: "Server parsed 50+ nested levels.", Payload: "50x Nested Query"}
		}
	}
	return Result{Name: "Deep Nesting allowed", Vulnerable: false}
}

// 17. Error Verbosity (Path Leaks)
func CheckErrorVerbosity(urlStr string) Result {
	payload := `{"query":"query { __typename(arg: \"wrong\") }"}`
	_, body, err := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	
	if err == nil && (strings.Contains(body, "/var/") || strings.Contains(body, ":\\Users")) {
		return Result{Name: "Path Disclosure", Vulnerable: true, Severity: "LOW", Description: "Absolute server path leaked in error.", Payload: payload}
	}
	return Result{Name: "Path Disclosure", Vulnerable: false}
}

// 18. Empty Array Panic
func CheckEmptyArrayPanic(urlStr string) Result {
	payload := `[]`
	resp, _, err := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	
	if err == nil && resp.StatusCode == 500 {
		return Result{Name: "Empty Array Crash", Vulnerable: true, Severity: "HIGH", Description: "Server 500'd on empty JSON array.", Payload: "[]"}
	}
	return Result{Name: "Empty Array Crash", Vulnerable: false}
}

// 19. Interface Discovery (Polymorphism)
func CheckInterfaceDiscovery(urlStr string) Result {
	q := `query { __schema { types { kind name possibleTypes { name } } } }`
	payload := fmt.Sprintf(`{"query":"%s"}`, q)
	_, body, err := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	
	if err == nil && strings.Contains(body, "INTERFACE") && strings.Contains(body, "possibleTypes") {
		return Result{Name: "Interface Discovery", Vulnerable: true, Severity: "INFO", Description: "Polymorphic relationships exposed.", Payload: q}
	}
	return Result{Name: "Interface Discovery", Vulnerable: false}
}

// 20. Playground Exposure (Common files)
func CheckPlaygroundExposure(urlStr string) Result {
	u, _ := url.Parse(urlStr)
	base := u.Scheme + "://" + u.Host + "/middleware/graphql/playground"
	resp, _, _ := sendRequest("GET", base, "", nil)
	if resp != nil && resp.StatusCode == 200 {
		return Result{Name: "Playground Middleware", Vulnerable: true, Severity: "LOW", Description: "Playground middleware exposed.", Payload: base}
	}
	return Result{Name: "Playground Middleware", Vulnerable: false}
}

// 21. Malformed JSON (Server robustness)
func CheckMalformJSON(urlStr string) Result {
	payload := `{"query": "query { __typename }"` // Missing closing brace
	resp, _, err := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	
	if err == nil && resp.StatusCode >= 500 {
		return Result{Name: "Malformed JSON Crash", Vulnerable: true, Severity: "MEDIUM", Description: "Server crashed (5xx) on malformed JSON.", Payload: payload}
	}
	return Result{Name: "Malformed JSON Crash", Vulnerable: false}
}
