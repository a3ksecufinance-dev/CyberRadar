package enricher

import (
	"net"
	"strings"
)

// GeoResult holds geo-enrichment data for an IP address.
type GeoResult struct {
	Country string
	ASN     string
}

// GeoEnricher resolves geographic and ASN metadata for IP addresses.
// Production: replace with MaxMind GeoIP2 database (geoip2-golang).
type GeoEnricher struct{}

// NewGeoEnricher creates a GeoEnricher.
func NewGeoEnricher() *GeoEnricher {
	return &GeoEnricher{}
}

// Lookup returns geo metadata for the given IP.
// Stub implementation: returns "PRIVATE" for RFC1918, empty otherwise.
// Replace body with MaxMind DB lookup in production.
func (g *GeoEnricher) Lookup(ip string) GeoResult {
	if ip == "" {
		return GeoResult{}
	}
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return GeoResult{}
	}
	if isPrivate(parsed) {
		return GeoResult{Country: "PRIVATE", ASN: "PRIVATE"}
	}
	// TODO: MaxMind GeoIP2 lookup
	// db, _ := geoip2.Open("/etc/crp/GeoLite2-City.mmdb")
	// record, _ := db.City(parsed)
	// return GeoResult{Country: record.Country.IsoCode, ASN: ...}
	return GeoResult{}
}

var privateRanges = []string{
	"10.0.0.0/8",
	"172.16.0.0/12",
	"192.168.0.0/16",
	"127.0.0.0/8",
	"::1/128",
	"fc00::/7",
}

var privateNets []*net.IPNet

func init() {
	for _, cidr := range privateRanges {
		_, n, _ := net.ParseCIDR(cidr)
		if n != nil {
			privateNets = append(privateNets, n)
		}
	}
}

func isPrivate(ip net.IP) bool {
	for _, n := range privateNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// SanctionedCountries is the list of ISO country codes blocked by default.
// Loaded from OPA data in production.
var SanctionedCountries = map[string]bool{}

// IsSanctioned returns true if the country is in the sanctioned list.
func IsSanctioned(country string) bool {
	return SanctionedCountries[strings.ToUpper(country)]
}
