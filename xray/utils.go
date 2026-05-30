package xray

import (
	"net"
	"strconv"
	"time"
	"errors"
	"xray-checker/models"
)

func PrepareProxyConfigs(proxies []*models.ProxyConfig) {
	for i := range proxies {
		proxies[i].Index = i

		if proxies[i].StableID == "" {
			proxies[i].StableID = proxies[i].GenerateStableID()
		}
	}
}

func IsConfigsEqual(old, new []*models.ProxyConfig) bool {
	if len(old) != len(new) {
		return false
	}

	oldMap := make(map[string]bool)
	newMap := make(map[string]bool)

	for _, cfg := range old {
		if cfg.StableID == "" {
			cfg.StableID = cfg.GenerateStableID()
		}
		oldMap[cfg.StableID] = true
	}

	for _, cfg := range new {
		if cfg.StableID == "" {
			cfg.StableID = cfg.GenerateStableID()
		}
		newMap[cfg.StableID] = true
	}

	for id := range oldMap {
		if !newMap[id] {
			return false
		}
	}

	for id := range newMap {
		if !oldMap[id] {
			return false
		}
	}

	return true
}


func CanConnect(ip string, port int, timeout float64) bool {
	address := net.JoinHostPort(ip, strconv.Itoa(port))

	conn, err := net.DialTimeout("tcp", address, time.Duration(timeout*float64(time.Second)))
	if err != nil {
		return false
	}
	defer conn.Close()

	return true
}

func CheckWhitelistsIsActive(timeout float64) (bool, error) {
	quad9OK := CanConnect("9.9.9.9", 53, timeout)
	yandexOK := CanConnect("77.88.8.8", 53, timeout)

	if !quad9OK && yandexOK {
		return true, nil
	}

	if quad9OK && yandexOK {
		return false, errors.New("whitelists are not active")
	}

	if !quad9OK && !yandexOK {
		return false, errors.New("no internet access")
	}

	return false, nil
}