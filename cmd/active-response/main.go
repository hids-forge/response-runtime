package main

import (
	"encoding/json"
	"fmt"
	"github.com/hids-forge/response-runtime/cmd/active-response/internal/version"
	"github.com/hids-forge/response-runtime/logging"
	"github.com/hids-forge/response-runtime/pkg/helper"
	"os"
	"strings"
	"time"

	"github.com/dop251/goja"
	"github.com/spf13/cobra"
)

const appVersion = "1.1"

func main() {
	// Get config
	helper.GetConfig()

	if len(os.Args) > 1 && os.Args[1] != "--child" {
		handleCLI()
		return
	}

	// Set up logging
	logFile := logging.SetupLogging(helper.LOG_FILE)
	defer logFile.Close()

	helper.WriteLog(os.Args[0], "response-runtime command started")

	// Read input from stdin and parse message
	msg := helper.SetupAndCheckMessage()
	if msg.Command < 0 {
		os.Exit(helper.OS_INVALID)
	}

	extraArgs := msg.Payload.Parameters.ExtraArgs
	if len(extraArgs) == 0 {
		fmt.Println("No subcommand found")
		return
	}

	subcommand := extraArgs[0]
	helper.WriteLog(os.Args[0], fmt.Sprintf("subcommand: %s", subcommand))

	switch subcommand {
	case "ar-updater":
		handleArUpdater(msg.Payload)
	case "block-ip":
		handleBlockIP(msg.Payload)
	case "unblock-ip":
		handleUnBlockIP(msg.Payload)
	case "get-info-av":
		handlePublishAVInfo(msg.Payload)
	case "kill-ramsomeware":
		handleKillRamsomware(msg.Payload)
	case "get-md5":
		handleGetMd5(msg.Payload)
	case "run-command":
		handleRunCommand(msg.Payload)
	case "js":
		handleJs(msg.Payload)
	default:
		helper.WriteLog(os.Args[0], "Unknown subcommand: "+subcommand)
	}

	os.Exit(0)
}

// handleCLI runs the cobra CLI for developer usage (e.g., self-update) and exits.
func handleCLI() {
	rootCmd := &cobra.Command{
		Use:           "active-response",
		Short:         "response-runtime active-response helper (local runtime and update CLI)",
		Long:          "active-response runs the response-runtime agent helpers locally. Use the update subcommand to fetch and apply signed releases when remote updates are enabled.",
		Example:       "active-response update --check\nactive-response update --manifest-url https://.../manifest.json",
		Version:       version.Full,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
	}

	registerUpdateCommands(rootCmd)

	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Print the response-runtime version",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), version.Full)
		},
	}
	rootCmd.AddCommand(versionCmd)

	// docs subcommand: print subcommand/payload guide
	docsCmd := &cobra.Command{
		Use:   "docs",
		Short: "Show subcommands and payload expectations",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Fprintln(cmd.OutOrStdout(), docSubcommands())
		},
	}
	rootCmd.AddCommand(docsCmd)

	// local-run-js: run a JS file locally (no MQTT), with optional env injection.
	var (
		jsFile      string
		playbook    string
		jsEnv       []string
		jsTimeout   time.Duration = timeout
		jsDebugFile string
		jsProgFile  string
		jsAlertFile string
		jsResultOut string
	)
	localRunCmd := &cobra.Command{
		Use:   "local-run-js",
		Short: "Run a JS file locally with helpers (no MQTT required)",
		Long:  "Executes a JavaScript file using the built-in helpers without MQTT. Useful for local playbook development and testing.",
		RunE: func(cmd *cobra.Command, args []string) error {
			selectedFile := strings.TrimSpace(jsFile)
			if selectedFile == "" {
				selectedFile = strings.TrimSpace(playbook)
			}
			if selectedFile == "" {
				return fmt.Errorf("--js or --playbook path is required")
			}
			scriptBytes, err := os.ReadFile(selectedFile)
			if err != nil {
				return err
			}
			// set timeout if provided
			if jsTimeout > 0 {
				timeout = jsTimeout
			}
			// inject env vars
			for _, kv := range jsEnv {
				parts := strings.SplitN(kv, "=", 2)
				if len(parts) != 2 {
					return fmt.Errorf("invalid --env %q (expected KEY=VALUE)", kv)
				}
				if err := os.Setenv(parts[0], parts[1]); err != nil {
					return fmt.Errorf("failed to set env %q: %w", kv, err)
				}
			}
			if strings.TrimSpace(jsDebugFile) != "" {
				debugTopic = jsDebugFile
			}
			if strings.TrimSpace(jsProgFile) != "" {
				progressTopic = jsProgFile
			}
			var alertCtx map[string]interface{}
			if strings.TrimSpace(jsAlertFile) != "" {
				raw, err := os.ReadFile(jsAlertFile)
				if err != nil {
					return fmt.Errorf("failed to read alert file: %w", err)
				}
				if err := json.Unmarshal(raw, &alertCtx); err != nil {
					return fmt.Errorf("invalid alert json: %w", err)
				}
			}
			result, progress := runJsWithContext(string(scriptBytes), alertCtx)
			fmt.Fprintln(cmd.OutOrStdout(), result)
			if len(progress) > 0 {
				out, _ := json.MarshalIndent(progress, "", "  ")
				fmt.Fprintln(cmd.OutOrStdout(), "progress:")
				fmt.Fprintln(cmd.OutOrStdout(), string(out))
			}
			if strings.TrimSpace(jsDebugFile) != "" {
				_ = os.WriteFile(jsDebugFile, []byte(result+"\n"), 0644)
			}
			if strings.TrimSpace(jsProgFile) != "" && len(progress) > 0 {
				if b, err := json.MarshalIndent(progress, "", " "); err == nil {
					_ = os.WriteFile(jsProgFile, b, 0644)
				}
			}
			if strings.TrimSpace(jsResultOut) != "" {
				payload := map[string]interface{}{
					"playbook": selectedFile,
					"result":   result,
					"progress": progress,
				}
				b, err := json.MarshalIndent(payload, "", "  ")
				if err != nil {
					return fmt.Errorf("failed to marshal result output: %w", err)
				}
				if err := os.WriteFile(jsResultOut, b, 0644); err != nil {
					return fmt.Errorf("failed to write result output: %w", err)
				}
			}
			return nil
		},
	}
	localRunCmd.Flags().StringVarP(&jsFile, "js", "f", "", "Path to JavaScript file to execute")
	localRunCmd.Flags().StringVar(&playbook, "playbook", "", "Path to a playbook file to execute (alias of --js)")
	localRunCmd.Flags().StringArrayVar(&jsEnv, "env", nil, "Environment variable to inject (KEY=VALUE); repeatable")
	localRunCmd.Flags().DurationVar(&jsTimeout, "timeout", jsTimeout, "Execution timeout (default matches agent)")
	localRunCmd.Flags().StringVar(&jsDebugFile, "debug-to", "", "Write debug output to file (local only; also sets debug_to)")
	localRunCmd.Flags().StringVar(&jsProgFile, "progress-to", "", "Write progress JSON to file (local only; also sets progress_to)")
	localRunCmd.Flags().StringVar(&jsAlertFile, "alert", "", "Path to alert JSON to inject as global 'alert' (simulates agent mode)")
	localRunCmd.Flags().StringVar(&jsResultOut, "result-to", "", "Write a structured JSON result bundle to file")
	rootCmd.AddCommand(localRunCmd)

	var jsPayloadFile string
	jsPayloadCmd := &cobra.Command{
		Use:    "exec-js-payload",
		Short:  "Run a JSON-described JS payload and emit JSON result",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(jsPayloadFile) == "" {
				return fmt.Errorf("--input is required")
			}
			raw, err := os.ReadFile(jsPayloadFile)
			if err != nil {
				return err
			}
			var payload struct {
				Script string                 `json:"script"`
				Alert  map[string]interface{} `json:"alert"`
			}
			if err := json.Unmarshal(raw, &payload); err != nil {
				return err
			}
			result, progress := runJsWithContext(payload.Script, payload.Alert)
			return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]interface{}{
				"result":   result,
				"progress": progress,
			})
		},
	}
	jsPayloadCmd.Flags().StringVar(&jsPayloadFile, "input", "", "Path to JSON payload file")
	rootCmd.AddCommand(jsPayloadCmd)

	// helpers subcommand: dump helperDocs as JSON
	helpersCmd := &cobra.Command{
		Use:   "helpers",
		Short: "List JS helpers (name, description, params)",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(helperDocs) == 0 {
				vm := goja.New()
				var prog []map[string]interface{}
				RegisterHelpers(vm, &prog)
			}
			out, err := json.MarshalIndent(helperDocs, "", "  ")
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), string(out))
			return nil
		},
	}
	rootCmd.AddCommand(helpersCmd)

	// docs subcommand: print subcommand/payload guide
	checkUpgradeCmd := &cobra.Command{
		Use:   "check-upgrade",
		Short: "Write log to active response.log to check upgrade",
		Run: func(cmd *cobra.Command, args []string) {
			helper.WriteCheckUpgradeLog("success", appVersion)
		},
	}
	rootCmd.AddCommand(checkUpgradeCmd)

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// func init() {
// 	// Initialize firewall rules DB and migrate schema
// 	dbPath := "firewall_rules.sqlite"
// 	gdb, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{})
// 	if err != nil {
// 		helper.WriteLog(os.Args[0], fmt.Sprintf("failed to open firewall DB %s: %v", dbPath, err))
// 		return
// 	}
// 	if err := gdb.AutoMigrate(&db.FirewallRule{}); err != nil {
// 		helper.WriteLog(os.Args[0], fmt.Sprintf("failed to migrate firewall rules table: %v", err))
// 		return
// 	}
// 	db.DB = gdb
// }
