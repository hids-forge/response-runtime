// Package updateclient exposes a thin wrapper around the shared updater core so
// response-runtime commands can check for and apply signed updates.
package updateclient

import (
	"context"
	_ "embed"
	"fmt"
	"runtime"
	"strings"
	"time"

	"github.com/spf13/cobra"

	updater "github.com/hids-forge/response-runtime/cmd/active-response/internal/updatercore"
	versionPkg "github.com/hids-forge/response-runtime/cmd/active-response/internal/version"
)

const (
	// ProductName identifies the binary this update helper belongs to.
	ProductName = "response-runtime"
	// DefaultTimeout bounds a single update check when callers do not provide a context.
	DefaultTimeout = 2 * time.Minute
)

// DefaultManifestURL points to the signed manifest used by updater-enabled builds.
// Builders can override it through ldflags.
var DefaultManifestURL = "https://updates.example.invalid/response-runtime/manifest.json"

// Options customizes a single updater invocation.
//
// ManifestURL overrides DefaultManifestURL when non-empty. CheckOnly performs a dry-run
// without downloading artifacts. SkipVerify bypasses signature validation (dangerous;
// useful only for diagnostics). SocksProxy routes all HTTP traffic through a SOCKS5 proxy
// (e.g., 127.0.0.1:1080). Timeout replaces DefaultTimeout when Update is invoked without a context.
type Options struct {
	CheckOnly   bool
	ManifestURL string
	SkipVerify  bool
	Timeout     time.Duration
	SocksProxy  string
}

// Embedded sample verification key for updater-enabled OSS builds.
//
//go:embed embedded/response-runtime_update_public.pem
var updatePublicKey []byte

// SubcommandOptions customizes the auto-generated Cobra update command enabled via
// EnableUpdateSubCommand. All fields are optional.
type SubcommandOptions struct {
	Use         string
	Short       string
	Long        string
	ManifestURL string
	Timeout     time.Duration
}

// New returns a configured updater.Client that knows how to validate response-runtime releases.
func New() *updater.Client {
	return &updater.Client{
		ProductName:    ProductName,
		ManifestURL:    DefaultManifestURL,
		CurrentVersion: versionPkg.Full,
		PublicKey:      updatePublicKey,
	}
}

// Update executes a complete update check/apply cycle using the shared updater client.
// Callers typically wrap this in a CLI command and format Result.Message for display.
func Update(ctx context.Context, opts Options) (updater.Result, error) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), timeout)
		defer cancel()
	}
	client := New()
	if strings.TrimSpace(opts.SocksProxy) != "" {
		client.SOCKS5Proxy = strings.TrimSpace(opts.SocksProxy)
	}
	targetURL := strings.TrimSpace(opts.ManifestURL)
	if targetURL == "" {
		targetURL = DefaultManifestURL
	}
	result, err := client.Update(ctx, updater.UpdateOptions{
		ManifestURL: targetURL,
		CheckOnly:   opts.CheckOnly,
		SkipVerify:  opts.SkipVerify,
	})
	if err != nil {
		return result, fmt.Errorf("update failed: %w", err)
	}
	return result, nil
}

// EnableUpdateSubCommand wires a ready-to-use "update" Cobra command into the provided
// parent. If parent is nil the command is returned without registration, allowing callers
// to attach it manually. Providing a SubcommandOptions argument overrides defaults.
func EnableUpdateSubCommand(parent *cobra.Command, opt ...SubcommandOptions) *cobra.Command {
	var cfg SubcommandOptions
	if len(opt) > 0 {
		cfg = opt[0]
	}
	use := strings.TrimSpace(cfg.Use)
	if use == "" {
		use = "update"
	}
	short := strings.TrimSpace(cfg.Short)
	if short == "" {
		short = fmt.Sprintf("Check for and apply %s updates", ProductName)
	}
	long := cfg.Long
	defaultURL := strings.TrimSpace(cfg.ManifestURL)
	if defaultURL == "" {
		defaultURL = DefaultManifestURL
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}

	var (
		checkOnly    bool
		manifestFlag string
		noVerify     bool
		timeoutFlag  time.Duration = timeout
		socksFlag    string
	)
	manifestFlag = defaultURL
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Long:  long,
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := Update(cmd.Context(), Options{
				ManifestURL: manifestFlag,
				CheckOnly:   checkOnly,
				SkipVerify:  noVerify,
				Timeout:     timeoutFlag,
				SocksProxy:  strings.TrimSpace(socksFlag),
			})
			if err != nil {
				return err
			}
			msg := result.Message
			if result.Updated && runtime.GOOS == "windows" && result.WindowsStagedBin != "" {
				msg += fmt.Sprintf("\nStaged binary: %s", result.WindowsStagedBin)
			}
			fmt.Fprintln(cmd.OutOrStdout(), msg)
			return nil
		},
	}
	cmd.Flags().BoolVar(&checkOnly, "check", false, "only check for updates")
	cmd.Flags().StringVar(&manifestFlag, "manifest-url", defaultURL, "override manifest URL")
	cmd.Flags().BoolVar(&noVerify, "no-verify", false, "skip signature verification (unsafe)")
	cmd.Flags().DurationVar(&timeoutFlag, "timeout", timeout, "override update timeout")
	cmd.Flags().StringVar(&socksFlag, "socks5", "", "route update requests through a SOCKS5 proxy (host:port)")

	if parent != nil {
		parent.AddCommand(cmd)
	}
	return cmd
}
