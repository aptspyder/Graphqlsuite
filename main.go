package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
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
	ColorPink   = "\033[1;35m" 
	ColorBold   = "\033[1m"
	ColorCyan   = "\033[36m"
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
	baselineBody string
)

type Result struct {
	Name        string
	Vulnerable  bool
	Severity    string 
	Description string
	Payload     string
	CurlCommand string // The Proof
}

type CheckFunc func(string) Result

type GraphQLResponse struct {
	Data   interface{} `json:"data"`
	Errors interface{} `json:"errors"`
}

// --- Main Execution ---

func main() {
	printBanner()

	flag.StringVar(&targetURL, "t", "", "Target URL")
	flag.StringVar(&proxyURL, "x", "", "Proxy URL")
	flag.StringVar(&headersRaw, "H", "", "Custom Headers")
	flag.IntVar(&concurrency, "c", 10, "Concurrency")
	flag.BoolVar(&force, "f", false, "Force scan")
	flag.BoolVar(&verbose, "v", false, "Verbose")
	flag.Parse()

	if targetURL == "" {
		fmt.Printf("%s[-] Target URL is required.%s\n", ColorRed, ColorReset)
		os.Exit(1)
	}

	setupClient()

	if !force {
		fmt.Printf("%s[*] Detecting GraphQL...%s\n", ColorBlue, ColorReset)
		if !detectGraphQL(targetURL) {
			fmt.Printf("%s[-] GraphQL not detected. Use -f to force.%s\n", ColorRed, ColorReset)
			os.Exit(1)
		}
		fmt.Printf("%s[+] GraphQL Confirmed!%s\n", ColorGreen, ColorReset)
	}

	baselineBody = getBaseline(targetURL)

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

	fmt.Printf("%s[*] Starting scan with %d checks (Live Exploit Mode)...%s\n\n", ColorBlue, len(checks), ColorReset)

	results := make(chan Result, len(checks))
	var wg sync.WaitGroup
	jobChan := make(chan CheckFunc, len(checks))

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for check := range jobChan {
				results <- check(targetURL)
			}
		}()
	}

	for _, c := range checks {
		jobChan <- c
	}
	close(jobChan)

	go func() {
		wg.Wait()
		close(results)
	}()

	for res := range results {
		if res.Vulnerable {
			color := ColorRed
			if res.Severity == "INFO" { color = ColorBlue }
			if res.Severity == "LOW" { color = ColorYellow }
			if res.Severity == "MEDIUM" { color = ColorYellow }

			fmt.Printf("%s[VULN] [%s] %s%s\n", color, res.Severity, res.Name, ColorReset)
			fmt.Printf("       %s\n", res.Description)
			
			// Print the Live Exploit Proof
			if res.CurlCommand != "" {
				fmt.Printf("%s       [PROOF] %s%s\n", ColorCyan, res.CurlCommand, ColorReset)
			}
			fmt.Println("") // Spacer
		} else if verbose {
			fmt.Printf("%s[SAFE] %s%s\n", ColorGreen, res.Name, ColorReset)
		}
	}
	
	fmt.Println("\n[*] Scan Complete.")
}

// --- Helpers ---

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
	fmt.Printf("%s    GraphQLSuite (v3.1 Live Exploit)%s\n\n", ColorPink, ColorReset)
}

func setupClient() {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	if proxyURL != "" {
		u, err := url.Parse(proxyURL)
		if err == nil { transport.Proxy = http.ProxyURL(u) }
	}
	client = &http.Client{ Transport: transport, Timeout: 15 * time.Second }
	
	headerMap = make(map[string]string)
	if headersRaw != "" {
		for _, p := range strings.Split(headersRaw, ",") {
			kv := strings.SplitN(p, ":", 2)
			if len(kv) == 2 { headerMap[strings.TrimSpace(kv[0])] = strings.TrimSpace(kv[1]) }
		}
	}
}

func sendRequest(method, urlStr, contentType string, body io.Reader) (*http.Response, string, error) {
	req, err := http.NewRequest(method, urlStr, body)
	if err != nil { return nil, "", err }
	
	req.Header.Set("User-Agent", "GraphQLSuite/3.1")
	if contentType != "" { req.Header.Set("Content-Type", contentType) }
	for k, v := range headerMap { req.Header.Set(k, v) }

	resp, err := client.Do(req)
	if err != nil { return nil, "", err }
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	return resp, string(respBody), nil
}

func detectGraphQL(urlStr string) bool {
	payload := `{"query":"query { __typename }"}`
	resp, body, err := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	return err == nil && resp.StatusCode == 200 && strings.Contains(body, "__typename")
}

func getBaseline(urlStr string) string {
	payload := `{"query":"query { __typename }"}`
	_, body, _ := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	return body
}

// Generates the CURL string for the report
func generateCurl(method, urlStr, contentType, body string) string {
	cmd := fmt.Sprintf("curl -X %s '%s'", method, urlStr)
	if contentType != "" {
		cmd += fmt.Sprintf(" -H 'Content-Type: %s'", contentType)
	}
	// Add custom headers if any
	for k, v := range headerMap {
		cmd += fmt.Sprintf(" -H '%s: %s'", k, v)
	}
	if body != "" {
		// Escape single quotes for shell safety (basic)
		safeBody := strings.ReplaceAll(body, "'", "'\\''")
		cmd += fmt.Sprintf(" -d '%s'", safeBody)
	}
	return cmd
}

// Strict Check: Must be valid JSON, have Data, NO Errors.
func isCleanSuccess(body string) bool {
	var g GraphQLResponse
	if err := json.Unmarshal([]byte(body), &g); err != nil { return false }
	return g.Data != nil && g.Errors == nil
}

// DoS Check: Reports VULN if server ALLOWS the attack (even if fast).
func analyzeDoS(body string, duration time.Duration) (bool, string) {
	var g GraphQLResponse
	if err := json.Unmarshal([]byte(body), &g); err != nil { return false, "" }
	
	// If errors exist (e.g. "Depth limit exceeded"), it is SAFE.
	if g.Errors != nil { return false, "" }
	
	// If we have Data and NO Errors, the server ACCEPTED the complexity.
	if g.Data != nil {
		if duration > 2000 * time.Millisecond {
			return true, "HIGH" // Slow response = Confirmed DoS
		}
		return true, "MEDIUM" // Fast response = Config Weakness (Potential DoS)
	}
	return false, ""
}

// --- CHECKS ---

func CheckIntrospection(urlStr string) Result {
	payload := `{"query":"query { __schema { queryType { name } } }"}`
	_, body, _ := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	if isCleanSuccess(body) && strings.Contains(body, "__schema") {
		return Result{
			Name: "Introspection Enabled", Vulnerable: true, Severity: "LOW", 
			Description: "Full schema discovery possible.", 
			CurlCommand: generateCurl("POST", urlStr, "application/json", payload),
		}
	}
	return Result{Name: "Introspection Enabled", Vulnerable: false}
}

func CheckAliasOverloading(urlStr string) Result {
	var b strings.Builder
	b.WriteString("query {")
	// Using 100 to match graphql-cop standard
	for i := 0; i < 100; i++ { b.WriteString(fmt.Sprintf("alias%d: __typename ", i)) }
	b.WriteString("}")
	payload := fmt.Sprintf(`{"query":"%s"}`, b.String())

	start := time.Now()
	_, body, _ := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	duration := time.Since(start)

	isVuln, severity := analyzeDoS(body, duration)
	if isVuln {
		desc := "Server accepted 100+ aliases."
		if severity == "HIGH" { desc += " caused significant lag." }
		return Result{
			Name: "Alias Overloading", Vulnerable: true, Severity: severity, 
			Description: desc,
			CurlCommand: generateCurl("POST", urlStr, "application/json", payload),
		}
	}
	return Result{Name: "Alias Overloading", Vulnerable: false}
}

func CheckBatchQuery(urlStr string) Result {
	payload := "[" + strings.Repeat(`{"query":"query { __typename }"},`, 10)
	payload = strings.TrimSuffix(payload, ",") + "]"
	start := time.Now()
	_, body, _ := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	duration := time.Since(start)
	
	if strings.HasPrefix(strings.TrimSpace(body), "[") && strings.Count(body, "__typename") >= 10 {
		severity := "MEDIUM"
		if duration > 2000 * time.Millisecond { severity = "HIGH" }
		return Result{
			Name: "Batch Queries", Vulnerable: true, Severity: severity, 
			Description: "Batching enabled (10+ queries).",
			CurlCommand: generateCurl("POST", urlStr, "application/json", payload),
		}
	}
	return Result{Name: "Batch Queries", Vulnerable: false}
}

func CheckDirectiveOverloading(urlStr string) Result {
	directives := strings.Repeat("@skip(if: false) ", 100)
	payload := fmt.Sprintf(`{"query":"query { __typename %s }"}`, directives)
	
	start := time.Now()
	_, body, _ := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	duration := time.Since(start)
	
	if isCleanSuccess(body) {
		severity := "MEDIUM"
		if duration > 2000 * time.Millisecond { severity = "HIGH" }
		return Result{
			Name: "Directive Overloading", Vulnerable: true, Severity: severity, 
			Description: "Accepted 100+ directives.",
			CurlCommand: generateCurl("POST", urlStr, "application/json", payload),
		}
	}
	return Result{Name: "Directive Overloading", Vulnerable: false}
}

func CheckFieldDuplication(urlStr string) Result {
	fields := strings.Repeat("__typename ", 500)
	payload := fmt.Sprintf(`{"query":"query { %s }"}`, fields)

	start := time.Now()
	_, body, _ := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	duration := time.Since(start)

	isVuln, severity := analyzeDoS(body, duration)
	if isVuln {
		return Result{
			Name: "Field Duplication", Vulnerable: true, Severity: severity, 
			Description: "Processed 500 duplicate fields.",
			CurlCommand: generateCurl("POST", urlStr, "application/json", payload),
		}
	}
	return Result{Name: "Field Duplication", Vulnerable: false}
}

func CheckCircularIntrospection(urlStr string) Result {
	q := `query { __schema { types { fields { type { fields { type { fields { type { name } } } } } } } } }`
	payload := fmt.Sprintf(`{"query":"%s"}`, q)
	
	start := time.Now()
	_, body, _ := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	duration := time.Since(start)
	
	isVuln, severity := analyzeDoS(body, duration)
	if isVuln {
		return Result{
			Name: "Circular Introspection", Vulnerable: true, Severity: severity, 
			Description: "Deep introspection executed without limits.",
			CurlCommand: generateCurl("POST", urlStr, "application/json", payload),
		}
	}
	return Result{Name: "Circular Introspection", Vulnerable: false}
}

func CheckCSRF_GET(urlStr string) Result {
	u, _ := url.Parse(urlStr)
	q := u.Query()
	q.Set("query", "query { __typename }")
	u.RawQuery = q.Encode()

	_, body, _ := sendRequest("GET", u.String(), "", nil)
	
	if isCleanSuccess(body) && len(body) > 0 {
		return Result{
			Name: "CSRF (GET Based)", Vulnerable: true, Severity: "MEDIUM", 
			Description: "API executed query via GET.",
			CurlCommand: fmt.Sprintf("curl -G '%s'", u.String()),
		}
	}
	return Result{Name: "CSRF (GET Based)", Vulnerable: false}
}

func CheckMutationOverGET(urlStr string) Result {
	u, _ := url.Parse(urlStr)
	q := u.Query()
	q.Set("query", "mutation { __typename }") 
	u.RawQuery = q.Encode()

	_, body, _ := sendRequest("GET", u.String(), "", nil)
	
	if body == baselineBody { return Result{Name: "Mutation over GET", Vulnerable: false} }
	if strings.Contains(body, "must be POST") || strings.Contains(body, "not supported") { return Result{Name: "Mutation over GET", Vulnerable: false} }

	if isCleanSuccess(body) {
		return Result{
			Name: "Mutation over GET", Vulnerable: true, Severity: "HIGH", 
			Description: "API processed mutation via GET.",
			CurlCommand: fmt.Sprintf("curl -G '%s'", u.String()),
		}
	}
	return Result{Name: "Mutation over GET", Vulnerable: false}
}

func CheckCSRF_POST_UrlEncoded(urlStr string) Result {
	data := url.Values{}
	data.Set("query", "query { __typename }")
	_, body, _ := sendRequest("POST", urlStr, "application/x-www-form-urlencoded", strings.NewReader(data.Encode()))
	
	if isCleanSuccess(body) {
		return Result{
			Name: "CSRF (POST UrlEncoded)", Vulnerable: true, Severity: "MEDIUM", 
			Description: "API accepts x-www-form-urlencoded.",
			CurlCommand: generateCurl("POST", urlStr, "application/x-www-form-urlencoded", data.Encode()),
		}
	}
	return Result{Name: "CSRF (POST UrlEncoded)", Vulnerable: false}
}

func CheckCSRF_POST_TextPlain(urlStr string) Result {
	payload := `{"query":"query { __typename }"}`
	_, body, _ := sendRequest("POST", urlStr, "text/plain", bytes.NewBufferString(payload))
	
	if isCleanSuccess(body) {
		return Result{
			Name: "CSRF (Text/Plain)", Vulnerable: true, Severity: "HIGH", 
			Description: "API accepts text/plain Content-Type.",
			CurlCommand: generateCurl("POST", urlStr, "text/plain", payload),
		}
	}
	return Result{Name: "CSRF (Text/Plain)", Vulnerable: false}
}

func CheckTracing(urlStr string) Result {
	payload := `{"query":"query { __typename }", "extensions": {"tracing": true}}`
	_, body, _ := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))

	if strings.Contains(body, "\"tracing\":") && strings.Contains(body, "duration") {
		return Result{
			Name: "GraphQL Tracing", Vulnerable: true, Severity: "INFO", 
			Description: "Performance tracing exposed.",
			CurlCommand: generateCurl("POST", urlStr, "application/json", payload),
		}
	}
	return Result{Name: "GraphQL Tracing", Vulnerable: false}
}

func CheckFieldSuggestions(urlStr string) Result {
	payload := `{"query":"query { __typenam }"}`
	_, body, _ := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))

	if strings.Contains(body, "Did you mean") {
		return Result{
			Name: "Field Suggestions", Vulnerable: true, Severity: "INFO", 
			Description: "Server suggests fields on typo.",
			CurlCommand: generateCurl("POST", urlStr, "application/json", payload),
		}
	}
	return Result{Name: "Field Suggestions", Vulnerable: false}
}

func CheckGraphiQL(urlStr string) Result {
	u, _ := url.Parse(urlStr)
	base := u.Scheme + "://" + u.Host
	paths := []string{"/graphiql", "/graphql/console", "/playground", "/explorer"}
	for _, p := range paths {
		resp, _, _ := sendRequest("GET", base+p, "", nil)
		if resp != nil && resp.StatusCode == 200 {
			return Result{
				Name: "GraphiQL/Playground", Vulnerable: true, Severity: "LOW", 
				Description: "Found at " + p,
				CurlCommand: fmt.Sprintf("curl '%s'", base+p),
			}
		}
	}
	return Result{Name: "GraphiQL/Playground", Vulnerable: false}
}

func CheckDebugMode(urlStr string) Result {
	payload := `{"query":"query { error_trigger }"}`
	_, body, _ := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	if strings.Contains(body, "stackTrace") || strings.Contains(body, "debugMessage") {
		return Result{
			Name: "Debug Mode", Vulnerable: true, Severity: "LOW", 
			Description: "Debug info leaked.",
			CurlCommand: generateCurl("POST", urlStr, "application/json", payload),
		}
	}
	return Result{Name: "Debug Mode", Vulnerable: false}
}

func CheckMethodNotAllowed(urlStr string) Result {
	payload := `{"query":"query { __typename }"}`
	for _, method := range []string{"PUT", "DELETE"} {
		_, body, _ := sendRequest(method, urlStr, "application/json", bytes.NewBufferString(payload))
		if isCleanSuccess(body) {
			return Result{
				Name: "HTTP Method Override", Vulnerable: true, Severity: "LOW", 
				Description: method + " allowed.",
				CurlCommand: generateCurl(method, urlStr, "application/json", payload),
			}
		}
	}
	return Result{Name: "HTTP Method Override", Vulnerable: false}
}

func CheckDeepNesting(urlStr string) Result {
	nest := strings.Repeat("{a", 50) + strings.Repeat("}", 50)
	payload := fmt.Sprintf(`{"query":"query %s"}`, nest)
	
	start := time.Now()
	_, body, _ := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	duration := time.Since(start)

	isVuln, severity := analyzeDoS(body, duration)
	if isVuln {
		return Result{
			Name: "Deep Nesting allowed", Vulnerable: true, Severity: severity, 
			Description: "Parsed 50+ nested levels.",
			CurlCommand: generateCurl("POST", urlStr, "application/json", payload),
		}
	}
	return Result{Name: "Deep Nesting allowed", Vulnerable: false}
}

func CheckErrorVerbosity(urlStr string) Result {
	payload := `{"query":"query { __typename(arg: \"wrong\") }"}`
	_, body, _ := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	if strings.Contains(body, "/var/") || strings.Contains(body, ":\\Users") {
		return Result{
			Name: "Path Disclosure", Vulnerable: true, Severity: "LOW", 
			Description: "Absolute path leaked.",
			CurlCommand: generateCurl("POST", urlStr, "application/json", payload),
		}
	}
	return Result{Name: "Path Disclosure", Vulnerable: false}
}

func CheckEmptyArrayPanic(urlStr string) Result {
	payload := `[]`
	resp, _, _ := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	if resp != nil && resp.StatusCode == 500 {
		return Result{
			Name: "Empty Array Crash", Vulnerable: true, Severity: "HIGH", 
			Description: "500 Error on empty array.",
			CurlCommand: generateCurl("POST", urlStr, "application/json", payload),
		}
	}
	return Result{Name: "Empty Array Crash", Vulnerable: false}
}

func CheckInterfaceDiscovery(urlStr string) Result {
	q := `query { __schema { types { kind name possibleTypes { name } } } }`
	payload := fmt.Sprintf(`{"query":"%s"}`, q)
	_, body, _ := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	if strings.Contains(body, "INTERFACE") && strings.Contains(body, "possibleTypes") {
		return Result{
			Name: "Interface Discovery", Vulnerable: true, Severity: "INFO", 
			Description: "Polymorphism exposed.",
			CurlCommand: generateCurl("POST", urlStr, "application/json", payload),
		}
	}
	return Result{Name: "Interface Discovery", Vulnerable: false}
}

func CheckPlaygroundExposure(urlStr string) Result {
	u, _ := url.Parse(urlStr)
	base := u.Scheme + "://" + u.Host + "/middleware/graphql/playground"
	resp, _, _ := sendRequest("GET", base, "", nil)
	if resp != nil && resp.StatusCode == 200 {
		return Result{
			Name: "Playground Middleware", Vulnerable: true, Severity: "LOW", 
			Description: "Exposed.",
			CurlCommand: fmt.Sprintf("curl '%s'", base),
		}
	}
	return Result{Name: "Playground Middleware", Vulnerable: false}
}

func CheckMalformJSON(urlStr string) Result {
	payload := `{"query": "query { __typename }"`
	resp, _, _ := sendRequest("POST", urlStr, "application/json", bytes.NewBufferString(payload))
	if resp != nil && resp.StatusCode >= 500 {
		return Result{
			Name: "Malformed JSON Crash", Vulnerable: true, Severity: "MEDIUM", 
			Description: "Server crashed.",
			CurlCommand: generateCurl("POST", urlStr, "application/json", payload),
		}
	}
	return Result{Name: "Malformed JSON Crash", Vulnerable: false}
}
