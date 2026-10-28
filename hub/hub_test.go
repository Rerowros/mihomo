package hub

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/metacubex/mihomo/config"
	"github.com/metacubex/mihomo/hub/route"
)

func TestControllerReloaderAppliesOverrides(t *testing.T) {
	parse := func() *config.Config {
		cfg, err := config.Parse([]byte("external-controller: 0.0.0.0:9090\n"))
		if err != nil {
			t.Fatal(err)
		}
		return cfg
	}

	// No secret in the file or on the command line: refused before anything
	// is applied.
	if _, err := controllerReloader(nil)(parse()); err == nil {
		t.Error("controller on all interfaces without a secret accepted")
	}

	// A secret given by -secret survives the reload.
	cfg := parse()
	if _, err := controllerReloader([]Option{WithSecret("s")})(cfg); err != nil {
		t.Errorf("with the -secret override: %v", err)
	}
	if cfg.Controller.Secret != "s" {
		t.Errorf("secret after reload = %q, want the override", cfg.Controller.Secret)
	}

	if _, err := controllerReloader([]Option{WithExternalControllerAllowInsecure(true)})(parse()); err != nil {
		t.Errorf("with the allow-insecure override: %v", err)
	}
}

// A config whose external-ui holds the core files starts the controller with
// the UI turned off: /ui does not list or serve the home directory.
func TestCoreDirectoryExternalUINotServed(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	cfg, err := config.Parse([]byte("external-controller: " + addr + "\nsecret: s\nexternal-ui: .\n"))
	if err != nil {
		t.Fatalf("config with external-ui: . refused: %v", err)
	}
	applyRoute(cfg)
	t.Cleanup(func() { route.ReCreateServer(&route.Config{}) })

	client := &http.Client{Timeout: 5 * time.Second}
	for _, path := range []string{"/ui/", "/ui/config.yaml"} {
		resp, err := client.Get("http://" + addr + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Errorf("GET %s: got %d, want 404", path, resp.StatusCode)
		}
	}
}
