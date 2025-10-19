package protos

// node
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative node/node.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative node/protocol.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative node/subscribe.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative node/point.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative node/latency.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative node/tag.proto

// statistic
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative statistic/config.proto

// config
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative config/config.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative config/log.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative config/inbound.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative config/bypass.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative config/dns.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative config/inbound.proto

// tools
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative --go-grpc_out=../protos --go-grpc_opt=paths=source_relative tools/tools.proto

// kv
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative --go-grpc_out=../protos --go-grpc_opt=paths=source_relative kv/kv.proto

// backup
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative --go-grpc_out=../protos --go-grpc_opt=paths=source_relative backup/backup.proto

// api
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative --go-grpc_out=../protos --go-grpc_opt=paths=source_relative api/statistic.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative --go-grpc_out=../protos --go-grpc_opt=paths=source_relative api/node.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative --go-grpc_out=../protos --go-grpc_opt=paths=source_relative api/config.proto
//go:generate protoc --go-grpc_out=../protos --go-grpc_opt=paths=source_relative api/backup.proto
//go:generate protoc --go-grpc_out=../protos --go-grpc_opt=paths=source_relative api/tools.proto
