module github.com/hids-forge/response-runtime

go 1.24.0

toolchain go1.24.11

// Enable resolving the local module during development/testing
replace github.com/hids-forge/response-runtime => ./

require github.com/spf13/cobra v1.6.1

require (
	github.com/Binject/debug v0.0.0-20230508195519-26db73212a7a
	github.com/andybalholm/brotli v1.0.5
	github.com/creack/pty v1.1.24
	github.com/dop251/goja v0.0.0-20250630131328-58d95d85e994
	github.com/dop251/goja_nodejs v0.0.0-20250409162600-f7acab6894b0
	github.com/eclipse/paho.mqtt.golang v1.5.0
	github.com/golang/snappy v0.0.4
	github.com/google/uuid v1.6.0
	github.com/iamacarpet/go-winpty v1.0.4
	github.com/klauspost/compress v1.16.7
	github.com/pelletier/go-toml/v2 v2.2.4
	github.com/pierrec/lz4/v4 v4.1.22
	github.com/refraction-networking/utls v1.5.4
	github.com/shirou/gopsutil/v3 v3.24.5
	github.com/shirou/gopsutil/v4 v4.25.11
	golang.org/x/crypto v0.25.0
	golang.org/x/net v0.27.0
	golang.org/x/sys v0.40.0
	gopkg.in/ini.v1 v1.67.1
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
	gopkg.in/yaml.v3 v3.0.1
	gorm.io/gorm v1.30.1
	modernc.org/sqlite v1.44.1
)

require (
	github.com/cloudflare/circl v1.3.3 // indirect
	github.com/dlclark/regexp2 v1.11.4 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/ebitengine/purego v0.9.1 // indirect
	github.com/gaukas/godicttls v0.0.4 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/go-sourcemap/sourcemap v2.1.4+incompatible // indirect
	github.com/google/pprof v0.0.0-20250317173921-a4b03ec1a45e // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/inconshreveable/mousetrap v1.0.1 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/quic-go/quic-go v0.37.4 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/tklauser/go-sysconf v0.3.16 // indirect
	github.com/tklauser/numcpus v0.11.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/sync v0.17.0 // indirect
	golang.org/x/text v0.20.0 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
