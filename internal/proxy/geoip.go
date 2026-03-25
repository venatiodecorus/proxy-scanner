package proxy

import (
	"fmt"
	"net"
	"sync"

	"github.com/oschwald/maxminddb-golang"
)

// GeoIPResult holds the geographic and network information for an IP address.
type GeoIPResult struct {
	Country string
	City    string
	ASN     int
	ASNOrg  string
}

// GeoIPLookup provides GeoIP lookups using MaxMind databases.
type GeoIPLookup struct {
	cityReader *maxminddb.Reader
	asnReader  *maxminddb.Reader
	mu         sync.RWMutex
}

// maxmindCityRecord is the struct we decode from the MaxMind City DB.
type maxmindCityRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
}

// maxmindASNRecord is the struct we decode from the MaxMind ASN DB.
type maxmindASNRecord struct {
	ASN int    `maxminddb:"autonomous_system_number"`
	Org string `maxminddb:"autonomous_system_organization"`
}

// GeoIPConfig holds paths to the MaxMind database files.
type GeoIPConfig struct {
	CityDBPath string
	ASNDBPath  string
}

// NewGeoIPLookup creates a new GeoIP lookup from MaxMind .mmdb files.
// Both databases are optional — if a path is empty, that lookup is skipped.
// Returns nil (not an error) if both paths are empty.
func NewGeoIPLookup(cfg GeoIPConfig) (*GeoIPLookup, error) {
	if cfg.CityDBPath == "" && cfg.ASNDBPath == "" {
		return nil, nil
	}

	g := &GeoIPLookup{}

	if cfg.CityDBPath != "" {
		reader, err := maxminddb.Open(cfg.CityDBPath)
		if err != nil {
			return nil, fmt.Errorf("opening city geoip database: %w", err)
		}
		g.cityReader = reader
	}

	if cfg.ASNDBPath != "" {
		reader, err := maxminddb.Open(cfg.ASNDBPath)
		if err != nil {
			// Close city reader if it was opened
			if g.cityReader != nil {
				g.cityReader.Close()
			}
			return nil, fmt.Errorf("opening asn geoip database: %w", err)
		}
		g.asnReader = reader
	}

	return g, nil
}

// Lookup returns GeoIP info for an IP address.
// Returns a zero-value GeoIPResult if lookup fails or GeoIP is not configured.
func (g *GeoIPLookup) Lookup(ipStr string) GeoIPResult {
	if g == nil {
		return GeoIPResult{}
	}

	ip := net.ParseIP(ipStr)
	if ip == nil {
		return GeoIPResult{}
	}

	g.mu.RLock()
	defer g.mu.RUnlock()

	var result GeoIPResult

	// City/Country lookup
	if g.cityReader != nil {
		var record maxmindCityRecord
		if err := g.cityReader.Lookup(ip, &record); err == nil {
			result.Country = record.Country.ISOCode
			if name, ok := record.City.Names["en"]; ok {
				result.City = name
			}
		}
	}

	// ASN lookup
	if g.asnReader != nil {
		var record maxmindASNRecord
		if err := g.asnReader.Lookup(ip, &record); err == nil {
			result.ASN = record.ASN
			result.ASNOrg = record.Org
		}
	}

	return result
}

// Close closes all MaxMind database readers.
func (g *GeoIPLookup) Close() error {
	if g == nil {
		return nil
	}
	if g.cityReader != nil {
		g.cityReader.Close()
	}
	if g.asnReader != nil {
		g.asnReader.Close()
	}
	return nil
}
