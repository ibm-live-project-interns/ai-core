package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

/* ---------------- NVD RESPONSE STRUCT ---------------- */

type nvdResponse struct {
	Vulnerabilities []struct {
		Cve struct {
			ID        string `json:"id"`
			Published string `json:"published"`

			Descriptions []struct {
				Lang  string `json:"lang"`
				Value string `json:"value"`
			} `json:"descriptions"`

			Metrics struct {
				CvssMetricV31 []nvdMetric `json:"cvssMetricV31"`
				CvssMetricV30 []nvdMetric `json:"cvssMetricV30"`
				CvssMetricV2  []nvdMetric `json:"cvssMetricV2"`
			} `json:"metrics"`

			Configurations interface{} `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

type nvdMetric struct {
	CvssData struct {
		BaseScore float64 `json:"baseScore"`
	} `json:"cvssData"`
}

/* ---------------- FETCH FROM NVD ---------------- */

// fetchRecentCVEsFromNVD fetches CVEs published in the last N days from NVD API v2.0
func fetchRecentCVEsFromNVD(days int) ([]CVE, error) {
	end := time.Now().UTC()
	start := end.AddDate(0, 0, -days)

	url := fmt.Sprintf(
		"https://services.nvd.nist.gov/rest/json/cves/2.0?pubStartDate=%s&pubEndDate=%s",
		start.Format(time.RFC3339),
		end.Format(time.RFC3339),
	)

	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("User-Agent", "ai-core/1.0")

	if key := os.Getenv("NVD_API_KEY"); key != "" {
		req.Header.Set("apiKey", key)
	}

	client := &http.Client{Timeout: 30 * time.Second}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("NVD returned status %d", resp.StatusCode)
	}

	var result nvdResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode NVD response: %w", err)
	}

	items := make([]CVE, 0, len(result.Vulnerabilities))

	for _, v := range result.Vulnerabilities {
		item := CVE{
			ID:        v.Cve.ID,
			Published: v.Cve.Published,
		}

		// English description
		for _, d := range v.Cve.Descriptions {
			if d.Lang == "en" {
				item.Description = d.Value
				break
			}
		}

		// CVSS Score (prefer v3.1 > v3.0 > v2.0)
		switch {
		case len(v.Cve.Metrics.CvssMetricV31) > 0:
			item.CVSSScore = v.Cve.Metrics.CvssMetricV31[0].CvssData.BaseScore
		case len(v.Cve.Metrics.CvssMetricV30) > 0:
			item.CVSSScore = v.Cve.Metrics.CvssMetricV30[0].CvssData.BaseScore
		case len(v.Cve.Metrics.CvssMetricV2) > 0:
			item.CVSSScore = v.Cve.Metrics.CvssMetricV2[0].CvssData.BaseScore
		}

		// Extract vendor/product from CPE
		nvdExtractVendorProduct(&item, v.Cve.Configurations)

		items = append(items, item)
	}

	return items, nil
}

/* ---------------- CPE PARSER ---------------- */

func nvdExtractVendorProduct(item *CVE, cfg interface{}) {
	data, err := json.Marshal(cfg)
	if err != nil {
		return
	}

	text := string(data)

	// Find first CPE string
	idx := strings.Index(text, "cpe:2.3:")
	if idx == -1 {
		return
	}

	cpe := text[idx:]
	parts := strings.Split(cpe, ":")

	if len(parts) >= 5 {
		item.Vendor = parts[3]
		item.Product = parts[4]
	}
}
