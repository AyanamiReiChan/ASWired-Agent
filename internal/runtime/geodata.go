package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/app/router"
	"github.com/xtls/xray-core/common/platform"
	"google.golang.org/protobuf/proto"
)

const geoReleaseURL = "https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/"

var geoAssetMu sync.Mutex

// Only the standard geoip/geosite datasets are fetched. ext: files remain
// operator-managed. Existing datasets are never replaced during a config apply.
func ensureGeoAssets(ctx context.Context, raw []byte) error {
	if len(raw) > 8<<20 {
		return errors.New("config exceeds 8 MiB")
	}
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return err
	}
	needed := map[string]bool{}
	var scan func(any)
	scan = func(value any) {
		switch v := value.(type) {
		case string:
			if strings.HasPrefix(v, "geoip:") {
				needed["geoip.dat"] = true
			}
			if strings.HasPrefix(v, "geosite:") {
				needed["geosite.dat"] = true
			}
		case []any:
			for _, item := range v {
				scan(item)
			}
		case map[string]any:
			for _, item := range v {
				scan(item)
			}
		}
	}
	scan(cfg["routing"])
	scan(cfg["dns"])
	if len(needed) == 0 {
		return nil
	}
	geoAssetMu.Lock()
	defer geoAssetMu.Unlock()
	client := &http.Client{Timeout: 90 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) > 8 || req.URL.Scheme != "https" {
			return errors.New("unsafe geodata redirect")
		}
		return nil
	}}
	for _, name := range []string{"geoip.dat", "geosite.dat"} {
		if !needed[name] {
			continue
		}
		path := platform.GetAssetLocation(name)
		if info, err := os.Stat(path); err == nil {
			if !info.Mode().IsRegular() || info.Size() == 0 {
				return fmt.Errorf("invalid geodata file: %s", path)
			}
			continue
		} else if !os.IsNotExist(err) {
			return err
		}
		if err := downloadGeoAsset(ctx, client, geoReleaseURL, name, path); err != nil {
			return fmt.Errorf("prepare %s: %w", name, err)
		}
	}
	return nil
}

func downloadGeoAsset(ctx context.Context, client *http.Client, base, name, path string) error {
	fetch := func(url string, limit int64) ([]byte, error) {
		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			return nil, err
		}
		res, err := client.Do(req)
		if err != nil {
			return nil, err
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("geodata HTTP %d", res.StatusCode)
		}
		data, err := io.ReadAll(io.LimitReader(res.Body, limit+1))
		if err != nil {
			return nil, err
		}
		if int64(len(data)) > limit {
			return nil, errors.New("geodata exceeds size limit")
		}
		return data, nil
	}
	checksum, err := fetch(base+name+".sha256sum", 4096)
	if err != nil {
		return err
	}
	fields := strings.Fields(string(checksum))
	if len(fields) == 0 || len(fields[0]) != 64 {
		return errors.New("invalid geodata checksum")
	}
	data, err := fetch(base+name, 64<<20)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if !strings.EqualFold(fields[0], hex.EncodeToString(sum[:])) {
		return errors.New("geodata SHA256 mismatch")
	}
	switch name {
	case "geoip.dat":
		var list router.GeoIPList
		if proto.Unmarshal(data, &list) != nil || len(list.Entry) == 0 {
			return errors.New("invalid GeoIP dataset")
		}
	case "geosite.dat":
		var list router.GeoSiteList
		if proto.Unmarshal(data, &list) != nil || len(list.Entry) == 0 {
			return errors.New("invalid GeoSite dataset")
		}
	default:
		return errors.New("unsupported geodata file")
	}
	return atomicWrite(path, data, 0600)
}
