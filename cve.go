package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

/* ---------------- CONFIG ---------------- */

const cacheFile = "cve_cache.json"
const freshnessWindow = 15 * time.Minute

/* ---------------- CVE STRUCT ---------------- */

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
   🔥 LOAD OR FETCH CVEs
   ====================================================== */

func EnsureRecentNetworkCVEs() error {

	cache, err := loadCacheFromFile()

	if err == nil && time.Since(cache.Timestamp) < freshnessWindow {

		cveMutex.Lock()
		recentCVEs = cache.CVEs
		cveMutex.Unlock()

		Logger.Println("✅ Loaded CVEs from cache file")
		return nil
	}

	Logger.Println("🌐 Fetching fresh CVEs from NVD")

	items, err := fetchRecentCVEsFromNVD(7)
	if err != nil {
		return err
	}

	filtered := filterNetworkCVEs(items)
	if len(filtered) == 0 {
		Logger.Println("⚠️ No network CVEs found — using all CVEs")
		filtered = items
	}

	saveCacheToFile(filtered)

	cveMutex.Lock()
	recentCVEs = filtered
	cveMutex.Unlock()

	Logger.Printf("✅ Stored %d CVEs", len(filtered))

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
   🔥 NETWORK CVE FILTER
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
   🔥 ACCESSOR
   ====================================================== */

func GetRecentCVEs() []CVE {

	cveMutex.RLock()
	defer cveMutex.RUnlock()

	out := make([]CVE, len(recentCVEs))
	copy(out, recentCVEs)

	return out
}

/* ======================================================
   🔥 GENERIC RAG BLOCK
   ====================================================== */

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

	var b strings.Builder
	b.WriteString("<Rag>\n")

	for _, c := range items {

		score := "N/A"
		if c.CVSSScore > 0 {
			score = fmt.Sprintf("%.1f", c.CVSSScore)
		}

		b.WriteString(
			fmt.Sprintf("%s - %s/%s - CVSS %s\n",
				c.ID, c.Vendor, c.Product, score),
		)
	}

	b.WriteString("</Rag>\n")
	return b.String()
}

/* ======================================================
   🔥 EVENT-AWARE RAG BLOCK
   ====================================================== */

func extractVendorFromEvent(text string) string {

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

func BuildCVERagBlockForEvent(event Event) string {

	items := GetRecentCVEs()
	if len(items) == 0 {
		return ""
	}

	vendor := extractVendorFromEvent(event.Message)

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

	var b strings.Builder
	b.WriteString("<Rag>\n")

	for _, c := range filtered {

		score := "N/A"
		if c.CVSSScore > 0 {
			score = fmt.Sprintf("%.1f", c.CVSSScore)
		}

		b.WriteString(
			fmt.Sprintf("%s - %s/%s - CVSS %s\n",
				c.ID, c.Vendor, c.Product, score),
		)
	}

	b.WriteString("</Rag>\n")
	return b.String()
}

/* ======================================================
   🔥 FIND RELEVANT CVEs FOR EVENT
   ====================================================== */

func FindRelevantCVEs(text string) []CVE {

	items := GetRecentCVEs()
	if len(items) == 0 {
		return nil
	}

	text = strings.ToLower(text)

	var result []CVE

	for _, c := range items {

		if strings.Contains(text, strings.ToLower(c.Vendor)) ||
			strings.Contains(text, strings.ToLower(c.Product)) {

			result = append(result, c)
		}
	}

	// fallback → most recent CVEs
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

/* ---------------- HELPERS ---------------- */

func parsePublished(s string) time.Time {

	if t, err := time.Parse(time.RFC3339Nano, s); err == nil {
		return t
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t
	}
	return time.Time{}
}

/* =======================================================
   🔥 BUILD RAG BLOCK FROM GIVEN CVE LIST (FINAL)
   ======================================================= */

   func BuildCVERagBlockFromList(items []CVE) string {

    if len(items) == 0 {
        return ""
    }

    // Sort newest first
    sort.Slice(items, func(i, j int) bool {
        return parsePublished(items[i].Published).
            After(parsePublished(items[j].Published))
    })

    // Limit to top 5
    if len(items) > 5 {
        items = items[:5]
    }

    var b strings.Builder
    b.WriteString("<Rag>\n")

    for _, c := range items {

        score := "N/A"
        if c.CVSSScore > 0 {
            score = fmt.Sprintf("%.1f", c.CVSSScore)
        }

        b.WriteString(
            fmt.Sprintf("%s - %s/%s - CVSS %s\n",
                c.ID, c.Vendor, c.Product, score),
        )
    }

    b.WriteString("</Rag>\n")
    return b.String()
}
