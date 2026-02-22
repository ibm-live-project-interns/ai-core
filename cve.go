package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ibm-live-project-interns/ingestor/shared/logger"
)

/* ---------------- CONFIG ---------------- */

const cacheFile = "cve_cache.json"
const freshnessWindow = 15 * time.Minute

/* ---------------- CVE STRUCT ---------------- */

// CVE represents a Common Vulnerability and Exposure entry from NVD
type CVE struct {
	ID          string  `json:"id"`
	Description string  `json:"description"`
	Published   string  `json:"published"`
	CVSSScore   float64 `json:"cvss_score"`
	Vendor      string  `json:"vendor"`
	Product     string  `json:"product"`
}

/* ---------------- FILE CACHE STRUCT ---------------- */

type cveCacheFile struct {
	Timestamp time.Time `json:"timestamp"`
	CVEs      []CVE     `json:"cves"`
}

/* ---------------- MEMORY STORAGE ---------------- */

var (
	recentCVEs []CVE
	cveMutex   sync.RWMutex
)

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

	logger.Info("Stored %d network CVEs", len(filtered))
	return nil
}

/* ---------------- FILE OPERATIONS ---------------- */

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
	networkVendors := []string{
		"cisco", "juniper", "fortinet", "mikrotik",
		"paloalto", "netgear", "dlink", "tplink",
		"ubiquiti", "arista",
	}

	var result []CVE
	for _, c := range items {
		if c.CVSSScore < 7.0 {
			continue
		}

		vendor := strings.ToLower(c.Vendor)
		for _, nv := range networkVendors {
			if vendor == nv {
				result = append(result, c)
				break
			}
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
   FIND RELEVANT CVEs FOR EVENT
   ====================================================== */

// FindRelevantCVEs matches CVEs to event text by vendor/product keywords
func FindRelevantCVEs(text string) []CVE {
	items := GetRecentCVEs()
	if len(items) == 0 {
		return nil
	}

	text = strings.ToLower(text)

	var result []CVE
	for _, c := range items {
		vendor := strings.ToLower(c.Vendor)
		product := strings.ToLower(c.Product)
		if (vendor != "" && strings.Contains(text, vendor)) ||
			(product != "" && strings.Contains(text, product)) {
			result = append(result, c)
		}
	}

	// fallback: most recent CVEs if no vendor/product match
	if len(result) == 0 {
		sort.Slice(items, func(i, j int) bool {
			return parsePublished(items[i].Published).
				After(parsePublished(items[j].Published))
		})

		if len(items) > 5 {
			items = items[:5]
		}
		return items
	}

	if len(result) > 5 {
		result = result[:5]
	}

	return result
}

/* ======================================================
   BUILD RAG BLOCK FROM CVE LIST
   ====================================================== */

// BuildCVERagBlock builds a RAG context string from the top recent CVEs
func BuildCVERagBlock() string {
	items := GetRecentCVEs()
	if len(items) == 0 {
		return ""
	}

	sort.Slice(items, func(i, j int) bool {
		return parsePublished(items[i].Published).
			After(parsePublished(items[j].Published))
	})

	if len(items) > 5 {
		items = items[:5]
	}

	return formatCVERagBlock(items)
}

// BuildCVERagBlockForMessage builds a vendor-aware RAG block for a given message
func BuildCVERagBlockForMessage(message string) string {
	items := GetRecentCVEs()
	if len(items) == 0 {
		return ""
	}

	vendor := extractVendorFromMessage(message)

	var filtered []CVE
	if vendor != "" {
		for _, c := range items {
			if strings.ToLower(c.Vendor) == vendor {
				filtered = append(filtered, c)
			}
		}
	}

	if len(filtered) == 0 {
		filtered = items
	}

	sort.Slice(filtered, func(i, j int) bool {
		return parsePublished(filtered[i].Published).
			After(parsePublished(filtered[j].Published))
	})

	if len(filtered) > 5 {
		filtered = filtered[:5]
	}

	return formatCVERagBlock(filtered)
}

// BuildCVERagBlockFromList builds a RAG block from a given CVE list
func BuildCVERagBlockFromList(items []CVE) string {
	if len(items) == 0 {
		return ""
	}

	sort.Slice(items, func(i, j int) bool {
		return parsePublished(items[i].Published).
			After(parsePublished(items[j].Published))
	})

	if len(items) > 5 {
		items = items[:5]
	}

	return formatCVERagBlock(items)
}

/* ---------------- HELPERS ---------------- */

func extractVendorFromMessage(text string) string {
	text = strings.ToLower(text)

	vendors := []string{
		"cisco", "juniper", "fortinet", "mikrotik",
		"palo alto", "netgear", "d-link", "tp-link",
		"ubiquiti", "arista",
	}

	for _, v := range vendors {
		if strings.Contains(text, v) {
			return strings.ReplaceAll(v, " ", "")
		}
	}

	return ""
}

func formatCVERagBlock(items []CVE) string {
	var b strings.Builder
	b.WriteString("<Rag>\n")

	for _, c := range items {
		score := "N/A"
		if c.CVSSScore > 0 {
			score = fmt.Sprintf("%.1f", c.CVSSScore)
		}
		b.WriteString(fmt.Sprintf("%s - %s/%s - CVSS %s\n",
			c.ID, c.Vendor, c.Product, score))
	}

	b.WriteString("</Rag>\n")
	return b.String()
}

func parsePublished(s string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}
