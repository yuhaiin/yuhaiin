package httpapi

//go:generate go run ../../cmd/httpapi-client-gen -input v2_routes.go -output ../../../yuhaiin-react/src/api/generated.ts
//go:generate go run ../../cmd/contract-ts-gen -input ../contract -output ../../../yuhaiin-react/src/api/generated-contracts.ts
