package protos

//go:generate protoc --go_out=. --go_opt=paths=source_relative config/config.proto
//go:generate protoc --go-grpc_out=. --go-grpc_opt=paths=source_relative grpc/config/config.proto
//go:generate protoc --go_out=. --go_opt=paths=source_relative node/node.proto
//go:generate protoc --go-grpc_out=. --go-grpc_opt=paths=source_relative grpc/node/node.proto
//go:generate protoc --go_out=. --go_opt=paths=source_relative statistic/config.proto
//go:generate protoc --go-grpc_out=. --go-grpc_opt=paths=source_relative grpc/statistic/config.proto
