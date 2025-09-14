package protos

// node
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative node/node.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative node/protocol/protocol.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative node/subscribe/subscribe.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative node/point/point.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative node/latency/latency.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative node/tag/tag.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative --go-grpc_out=../protos --go-grpc_opt=paths=source_relative node/grpc/node.proto

// statistic
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative statistic/config.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative --go-grpc_out=../protos --go-grpc_opt=paths=source_relative statistic/grpc/config.proto

// config
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative config/config.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative --go-grpc_out=../protos --go-grpc_opt=paths=source_relative config/grpc/config.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative config/log/log.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative config/bypass/bypass.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative config/dns/dns.proto
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative config/listener/listener.proto

// tools
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative --go-grpc_out=../protos --go-grpc_opt=paths=source_relative tools/tools.proto

// kv
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative --go-grpc_out=../protos --go-grpc_opt=paths=source_relative kv/kv.proto

// backup
//go:generate protoc --go_out=../protos --go_opt=paths=source_relative --go-grpc_out=../protos --go-grpc_opt=paths=source_relative backup/backup.proto
