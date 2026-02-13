module github.com/go-tangra/go-tangra-client

go 1.25.4

require (
	github.com/go-tangra/go-tangra-executor v0.0.0
	github.com/go-tangra/go-tangra-ipam v0.0.0
	github.com/go-tangra/go-tangra-lcm v0.0.0
	github.com/minio/selfupdate v0.6.0
	github.com/spf13/cobra v1.10.2
	github.com/spf13/viper v1.18.2
	github.com/tx7do/go-scripts v0.0.5
	golang.org/x/sync v0.19.0
	google.golang.org/grpc v1.78.0
	gopkg.in/yaml.v3 v3.0.1
)

require (
	aead.dev/minisign v0.2.0 // indirect
	buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go v1.36.11-20251209175733-2a1774d88802.1 // indirect
	github.com/fsnotify/fsnotify v1.9.0 // indirect
	github.com/go-kratos/aegis v0.2.0 // indirect
	github.com/go-kratos/kratos/v2 v2.9.2 // indirect
	github.com/go-playground/form/v4 v4.3.0 // indirect
	github.com/google/gnostic v0.7.1 // indirect
	github.com/google/gnostic-models v0.7.1 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/mux v1.8.1 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/magiconair/properties v1.8.7 // indirect
	github.com/menta2k/protoc-gen-redact/v3 v3.0.0-20251106150014-896cdd075ab1 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/pelletier/go-toml/v2 v2.1.0 // indirect
	github.com/sagikazarmark/locafero v0.4.0 // indirect
	github.com/sagikazarmark/slog-shim v0.1.0 // indirect
	github.com/sourcegraph/conc v0.3.0 // indirect
	github.com/spf13/afero v1.15.0 // indirect
	github.com/spf13/cast v1.7.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/subosito/gotenv v1.6.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v3 v3.0.4 // indirect
	golang.org/x/crypto v0.47.0 // indirect
	golang.org/x/exp v0.0.0-20260112195511-716be5621a96 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260120221211-b8f7ae30c516 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260120221211-b8f7ae30c516 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/ini.v1 v1.67.0 // indirect
)

replace (
	github.com/go-tangra/go-tangra-executor => ../go-tangra-executor
	github.com/go-tangra/go-tangra-ipam => ../go-tangra-ipam
	github.com/go-tangra/go-tangra-lcm => ../go-tangra-lcm
)
