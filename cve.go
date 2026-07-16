package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/ibm-live-project-interns/ingestor/shared/logger"
)

/* ======================================================
   CONFIG
   ====================================================== */

const cacheFile = "cve_cache.json"
const freshnessWindow = 15 * time.Minute

// Scoring weights — tuned for network security domain
const (
	wCVEIDRef       = 20 // CVE ID explicitly referenced in event
	wVendorExact    = 10 // vendor string is a substring of event text
	wVendorToken    = 5  // individual vendor word matches event token
	wProductExact   = 8  // product string is a substring of event text
	wProductToken   = 4  // individual product word matches event token
	wDescToken      = 2  // description word matches event token
	wProtocolMatch  = 3  // same network protocol in event and CVE desc
	wVulnTypeMatch  = 2  // same vulnerability class in event and CVE desc
	maxDescMatches  = 8  // cap description token contributions
	minScore        = 3  // minimum relevance score to include a CVE
	maxResults      = 5  // max CVEs returned per event
)

// cvssMultiplier returns 1 + cvss/20 so CVSS 10 = 1.5×, CVSS 7 = 1.35×, CVSS 0 = 1×
func cvssMultiplier(cvss float64) float64 {
	if cvss <= 0 {
		return 1.0
	}
	return 1.0 + (cvss / 20.0)
}

/* ======================================================
   DOMAIN KNOWLEDGE — Vendor Aliases
   Maps canonical vendor name (lowercased, no spaces) →
   list of aliases that should also trigger a match.
   ====================================================== */

var vendorAliases = map[string][]string{
	"cisco": {
		"ios", "iosxe", "ios-xe", "ios xe", "nxos", "nx-os",
		"asa", "catalyst", "aironet", "isr", "csr", "asdm",
		"meraki", "webex", "ucs", "staros", "csco",
	},
	"juniper": {
		"junos", "junos-os", "junos os", "srx", "mx-series",
		"qfx", "ex-series", "ptx", "contrail", "space",
	},
	"fortinet": {
		"fortigate", "fortios", "forti", "fortimanager",
		"fortianalyzer", "fortiwifi", "fortiap", "fortinac",
		"fortiswitch", "forticlient",
	},
	"paloalto": {
		"pan-os", "panos", "panorama", "globalprotect", "pan os",
	},
	"mikrotik": {
		"routeros", "winbox", "router os",
	},
	"checkpoint": {
		"gaia", "check point", "smartcenter", "smartdashboard",
	},
	"f5": {
		"big-ip", "bigip", "tmos", "icontrol", "f5 big",
	},
	"aruba": {
		"arubos", "arubaos", "clearpass", "aruba os",
	},
	"ubiquiti": {
		"unifi", "edgeos", "edgerouter", "airmax", "unifi os",
	},
	"arista": {
		"eos", "arista eos", "cloudvision",
	},
	"netgear": {
		"prosafe", "readynas", "nighthawk",
	},
	"sonicwall": {
		"sonicos", "sonic os",
	},
	"watchguard": {
		"fireware", "firebox",
	},
	"zyxel": {
		"zywall", "usg", "zyxel usg",
	},
	"dlink": {
		"d-link", "d link", "dap-",
	},
	"tplink": {
		"tp-link", "tp link", "tl-", "archer",
	},
	"extreme": {
		"exos", "voss", "extremexos",
	},
	"huawei": {
		"vrp", "cloudengine", "ar router", "usg huawei",
	},
}

/* ======================================================
   DOMAIN KNOWLEDGE — Network Protocols
   A token match in BOTH event and CVE description adds wProtocolMatch.
   ====================================================== */

var networkProtocols = []string{
	// Routing
	"bgp", "ospf", "eigrp", "isis", "rip", "mpls", "ldp", "rsvp", "bfd",
	// Switching
	"stp", "rstp", "mstp", "vlan", "vxlan", "gre", "lacp", "lldp", "cdp",
	// Security
	"ipsec", "vpn", "ssh", "ssl", "tls", "radius", "tacacs",
	// Management
	"snmp", "netflow", "sflow", "dhcp", "dns", "ntp", "syslog",
	// Other
	"nat", "acl", "qos", "pim", "mld", "igmp",
}

/* ======================================================
   DOMAIN KNOWLEDGE — Vulnerability Types
   Same dual-match strategy as protocols.
   ====================================================== */

var vulnTypes = []string{
	"rce", "remote code execution", "arbitrary code",
	"overflow", "buffer overflow", "stack overflow", "heap overflow", "out-of-bounds",
	"injection", "sql injection", "command injection", "os command",
	"path traversal", "directory traversal",
	"authentication bypass", "auth bypass", "unauthenticated",
	"privilege escalation", "elevation of privilege",
	"denial of service", "memory corruption",
	"use after free", "null pointer", "integer overflow",
	"xss", "csrf", "ssrf", "xxe", "deserialization",
	"credential", "hardcoded", "default password", "backdoor",
}

/* ======================================================
   STOP WORDS — filtered out before token scoring
   ====================================================== */

var stopWords = map[string]bool{
	// Articles / prepositions
	"a": true, "an": true, "the": true, "in": true, "on": true, "at": true,
	"to": true, "of": true, "for": true, "with": true, "by": true,
	"from": true, "as": true, "into": true, "through": true,
	"before": true, "after": true, "via": true, "per": true,
	// Conjunctions / pronouns
	"and": true, "or": true, "but": true, "not": true, "no": true,
	"nor": true, "so": true, "yet": true, "both": true, "either": true,
	"that": true, "this": true, "which": true, "who": true, "whom": true,
	"its": true, "it": true, "if": true, "than": true, "when": true,
	"where": true, "how": true, "what": true, "also": true,
	// Auxiliary verbs
	"is": true, "are": true, "was": true, "were": true, "be": true,
	"been": true, "being": true, "have": true, "has": true, "had": true,
	"do": true, "does": true, "did": true, "will": true, "would": true,
	"could": true, "should": true, "may": true, "might": true, "can": true,
	// Common CVE prose words that carry no signal
	"allows": true, "allow": true, "attacker": true, "user": true,
	"system": true, "using": true, "used": true,
	"these": true, "those": true, "them": true, "they": true, "their": true,
}

/* ======================================================
   CVE STRUCT
   ====================================================== */

type CVE struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	Published   string  `json:"published"`
	CVSSScore   float64 `json:"cvss_score"`
	Vendor      string  `json:"vendor"`
	Product     string  `json:"product"`
}

/* ======================================================
   FILE CACHE STRUCT
   ====================================================== */

type cveCacheFile struct {
	Timestamp time.Time `json:"timestamp"`
	CVEs      []CVE     `json:"cves"`
}

/* ======================================================
   MEMORY STORAGE
   ====================================================== */

var (
	recentCVEs []CVE
	cveMutex   sync.RWMutex
)

/* ======================================================
   IDF INDEX
   Precomputed when CVEs are cached. Gives rare, specific
   terms (e.g. "ios-xe", "fortigate") much higher weight
   than common terms (e.g. "remote", "network", "code").
   ====================================================== */

var (
	termDF    map[string]int // term → number of CVEs containing it
	totalDocs int
	idfMutex  sync.RWMutex
)

// buildIDF computes per-term document frequencies across all CVEs.
// Called whenever the CVE cache is refreshed.
func buildIDF(items []CVE) {
	df := make(map[string]int, 2048)
	for _, c := range items {
		// Collect unique tokens across all text fields of this CVE
		seen := make(map[string]bool, 64)
		allText := strings.ToLower(c.Vendor + " " + c.Product + " " + c.Description)
		for _, tok := range tokenize(allText) {
			if !seen[tok] {
				df[tok]++
				seen[tok] = true
			}
		}
	}
	idfMutex.Lock()
	termDF = df
	totalDocs = len(items)
	idfMutex.Unlock()
}

// idfWeight returns the BM25+ IDF for a term:
//
//	log((N+1)/(df+1) + 1)
//
// Rare terms score high (≈4.6 for df=1/N=200).
// Universal terms score low (≈0.69 for df=N).
func idfWeight(term string) float64 {
	idfMutex.RLock()
	df := termDF[term]
	n := totalDocs
	idfMutex.RUnlock()
	if n == 0 {
		return 1.0
	}
	return math.Log(float64(n+1)/float64(df+1) + 1)
}

/* ======================================================
   LOAD OR FETCH CVEs
   ====================================================== */

// EnsureRecentNetworkCVEs loads CVEs from cache or fetches fresh from NVD
func EnsureRecentNetworkCVEs() error {
	cache, err := loadCacheFromFile()
	if err == nil && time.Since(cache.Timestamp) < freshnessWindow {
		cveMutex.Lock()
		recentCVEs = cache.CVEs
		cveMutex.Unlock()
		buildIDF(cache.CVEs)
		logger.Info("Loaded %d CVEs from cache file", len(cache.CVEs))
		return nil
	}

	logger.Info("Fetching fresh CVEs from NVD...")
	items, err := fetchRecentCVEsFromNVD(7)
	if err != nil {
		logger.Error("Failed to fetch CVEs from NVD: %v", err)
		return err
	}

	filtered := filterNetworkCVEs(items)
	if len(filtered) == 0 {
		logger.Warn("No network CVEs found - using all %d CVEs", len(items))
		filtered = items
	}

	saveCacheToFile(filtered)

	cveMutex.Lock()
	recentCVEs = filtered
	cveMutex.Unlock()
	buildIDF(filtered)

	logger.Info("Stored %d network CVEs", len(filtered))
	return nil
}

/* ======================================================
   FILE OPERATIONS
   ====================================================== */

func loadCacheFromFile() (*cveCacheFile, error) {
	data, err := os.ReadFile(cacheFile)
	if err != nil {
		return nil, err
	}

	var cache cveCacheFile
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, err
	}

	return &cache, nil
}

func saveCacheToFile(items []CVE) {
	cache := cveCacheFile{
		Timestamp: time.Now().UTC(),
		CVEs:      items,
	}
	data, _ := json.MarshalIndent(cache, "", "  ")
	_ = os.WriteFile(cacheFile, data, 0644)
}

/* ======================================================
   NETWORK CVE FILTER
   ====================================================== */

func filterNetworkCVEs(items []CVE) []CVE {
	networkVendors := map[string]bool{
		"cisco": true, "juniper": true, "fortinet": true, "mikrotik": true,
		"paloalto": true, "netgear": true, "dlink": true, "tplink": true,
		"ubiquiti": true, "arista": true, "f5": true, "checkpoint": true,
		"sonicwall": true, "watchguard": true, "zyxel": true, "extreme": true,
		"huawei": true, "aruba": true,
	}

	var result []CVE
	for _, c := range items {
		if c.CVSSScore < 7.0 {
			continue
		}
		if networkVendors[strings.ToLower(c.Vendor)] {
			result = append(result, c)
		}
	}
	return result
}

/* ======================================================
   ACCESSOR
   ====================================================== */

// GetRecentCVEs returns a thread-safe copy of the cached CVEs
func GetRecentCVEs() []CVE {
	cveMutex.RLock()
	defer cveMutex.RUnlock()

	out := make([]CVE, len(recentCVEs))
	copy(out, recentCVEs)
	return out
}

/* ======================================================
   TOKENIZER
   ====================================================== */

// tokenize splits text into lowercase meaningful tokens, removing stop words
// and single-char tokens. Pure stdlib, no regex.
func tokenize(text string) []string {
	text = strings.ToLower(text)

	// Split on any non-alphanumeric character
	tokens := strings.FieldsFunc(text, func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	})

	unique := make(map[string]bool, len(tokens))
	out := tokens[:0] // reuse backing array
	for _, tok := range tokens {
		if len(tok) < 2 || stopWords[tok] || unique[tok] {
			continue
		}
		unique[tok] = true
		out = append(out, tok)
	}
	return out
}

// tokenSet builds a set from tokenize for O(1) lookup
func tokenSet(text string) map[string]bool {
	toks := tokenize(text)
	set := make(map[string]bool, len(toks))
	for _, t := range toks {
		set[t] = true
	}
	return set
}

/* ======================================================
   SCORING ENGINE
   ====================================================== */

type scoredCVE struct {
	CVE   CVE
	Score float64
}

// scoreCVE computes a relevance score for one CVE against an event.
// eventText must already be lowercased. eventToks is the token set of eventText.
func scoreCVE(cve CVE, eventToks map[string]bool, eventText string) float64 {
	score := 0.0

	// ── CVE ID direct reference ──────────────────────────────────
	if strings.Contains(eventText, strings.ToLower(cve.ID)) {
		score += wCVEIDRef
	}

	// ── Vendor matching ──────────────────────────────────────────
	vendor := strings.ToLower(strings.TrimSpace(cve.Vendor))
	canonicalVendor := strings.ReplaceAll(vendor, " ", "")
	canonicalVendor = strings.ReplaceAll(canonicalVendor, "-", "")

	if vendor != "" && strings.Contains(eventText, vendor) {
		score += wVendorExact
	}
	for _, tok := range tokenize(vendor) {
		if eventToks[tok] {
			score += wVendorToken
		}
	}
	// Vendor aliases (e.g. "cisco" → "ios", "iosxe", "asa", …)
	for _, alias := range vendorAliases[canonicalVendor] {
		if strings.Contains(eventText, alias) {
			score += wVendorToken
			break // count alias group once to avoid double-boosting
		}
	}

	// ── Product matching ─────────────────────────────────────────
	product := strings.ToLower(strings.TrimSpace(cve.Product))
	if product != "" && strings.Contains(eventText, product) {
		score += wProductExact
	}
	for _, tok := range tokenize(product) {
		if len(tok) > 2 && eventToks[tok] {
			score += wProductToken
		}
	}

	// ── Description token overlap (IDF-weighted) ─────────────────
	// Rare terms (e.g. "fortigate", "bgp-hijack") score higher than
	// common prose terms (e.g. "remote", "network", "code").
	descLower := strings.ToLower(cve.Description)
	descToks := tokenize(descLower)
	matched := 0
	for _, tok := range descToks {
		if len(tok) > 3 && eventToks[tok] {
			score += float64(wDescToken) * idfWeight(tok)
			matched++
			if matched >= maxDescMatches {
				break
			}
		}
	}

	// ── Network protocol co-occurrence ───────────────────────────
	for _, proto := range networkProtocols {
		if strings.Contains(eventText, proto) && strings.Contains(descLower, proto) {
			score += wProtocolMatch
		}
	}

	// ── Vulnerability type co-occurrence ─────────────────────────
	for _, vt := range vulnTypes {
		if strings.Contains(eventText, vt) && strings.Contains(descLower, vt) {
			score += wVulnTypeMatch
		}
	}

	// ── CVSS severity multiplier ─────────────────────────────────
	// CVSS 10 → 1.5×, CVSS 7 → 1.35×, CVSS 0 → 1×
	score *= cvssMultiplier(cve.CVSSScore)

	return score
}

/* ======================================================
   FIND RELEVANT CVEs FOR EVENT
   ====================================================== */

// FindRelevantCVEs scores all cached CVEs against the event text and returns
// up to maxResults CVEs with score >= minScore, sorted by relevance descending.
// No random fallback — if nothing scores, an empty slice is returned so the
// Watson prompt is not polluted with unrelated CVEs.
func FindRelevantCVEs(text string) []CVE {
	items := GetRecentCVEs()
	if len(items) == 0 {
		return nil
	}

	eventText := strings.ToLower(text)
	eventToks := tokenSet(eventText)

	scored := make([]scoredCVE, 0, len(items))
	for _, c := range items {
		s := scoreCVE(c, eventToks, eventText)
		if s >= minScore {
			scored = append(scored, scoredCVE{CVE: c, Score: s})
		}
	}

	if len(scored) == 0 {
		logger.Info("[CVE] No CVEs scored above threshold for event: %.80s…", text)
		return nil
	}

	sort.Slice(scored, func(i, j int) bool {
		return scored[i].Score > scored[j].Score
	})

	if len(scored) > maxResults {
		scored = scored[:maxResults]
	}

	out := make([]CVE, len(scored))
	for i, sc := range scored {
		out[i] = sc.CVE
	}

	logger.Info("[CVE] %d relevant CVEs found (top score: %.1f)", len(out), scored[0].Score)
	return out
}

/* ======================================================
   BUILD RAG BLOCK FROM CVE LIST
   ====================================================== */

// BuildCVERagBlock builds a RAG context string from the top recent CVEs
// (used when no event message is available)
func BuildCVERagBlock() string {
	items := GetRecentCVEs()
	if len(items) == 0 {
		return ""
	}

	sort.Slice(items, func(i, j int) bool {
		return parsePublished(items[i].Published).
			After(parsePublished(items[j].Published))
	})

	if len(items) > maxResults {
		items = items[:maxResults]
	}

	return formatCVERagBlock(items)
}

// BuildCVERagBlockForMessage builds a scored, vendor-aware RAG block for a given message
func BuildCVERagBlockForMessage(message string) string {
	items := FindRelevantCVEs(message)
	if len(items) == 0 {
		// Nothing scored — omit RAG block entirely rather than injecting noise
		return ""
	}
	return formatCVERagBlock(items)
}

// BuildCVERagBlockFromList builds a RAG block from a provided CVE list
func BuildCVERagBlockFromList(items []CVE) string {
	if len(items) == 0 {
		return ""
	}

	sort.Slice(items, func(i, j int) bool {
		return parsePublished(items[i].Published).
			After(parsePublished(items[j].Published))
	})

	if len(items) > maxResults {
		items = items[:maxResults]
	}

	return formatCVERagBlock(items)
}

/* ======================================================
   VENDOR EXTRACTION (used by BuildCVERagBlockForMessage callers)
   ====================================================== */

func extractVendorFromMessage(text string) string {
	lower := strings.ToLower(text)

	// Check canonical names and their aliases
	for canonical, aliases := range vendorAliases {
		if strings.Contains(lower, canonical) {
			return canonical
		}
		for _, alias := range aliases {
			if strings.Contains(lower, alias) {
				return canonical
			}
		}
	}

	return ""
}

/* ======================================================
   RAG BLOCK FORMATTER
   ======================================================
   Output format:
     <Rag>
     CVE-2024-20418 [Cisco/IOS XE] CVSS 10.0
     Unauthenticated RCE in web UI via crafted HTTP request

     CVE-2024-21762 [Fortinet/FortiOS] CVSS 9.6
     Out-of-bounds write in SSL-VPN allows remote code execution
     </Rag>
   ====================================================== */

func formatCVERagBlock(items []CVE) string {
	var b strings.Builder
	b.WriteString("<Rag>\n")

	for _, c := range items {
		cvssStr := "N/A"
		if c.CVSSScore > 0 {
			cvssStr = fmt.Sprintf("%.1f", c.CVSSScore)
		}

		// Header line: ID [Vendor/Product] CVSS X.X
		b.WriteString(fmt.Sprintf("%s [%s/%s] CVSS %s\n",
			c.ID, c.Vendor, c.Product, cvssStr))

		// Description snippet — first 120 chars so Watson understands the vulnerability
		desc := strings.TrimSpace(c.Description)
		if len(desc) > 120 {
			// Trim to last complete word within 120 chars
			desc = desc[:120]
			if i := strings.LastIndexByte(desc, ' '); i > 80 {
				desc = desc[:i]
			}
			desc += "…"
		}
		if desc != "" {
			b.WriteString(desc)
			b.WriteByte('\n')
		}

		b.WriteByte('\n')
	}

	b.WriteString("</Rag>\n")
	return b.String()
}

/* ======================================================
   HELPERS
   ====================================================== */

func parsePublished(s string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}
