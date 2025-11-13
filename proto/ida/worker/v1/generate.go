package workerv1

//go:generate protoc -I../../.. --go_out=../../../.. --go_opt=paths=source_relative --connect-go_out=../../../.. --connect-go_opt=paths=source_relative ida/worker/v1/service.proto
//go:generate protoc -I../../.. --python_out=../../../../python/worker/gen ida/worker/v1/service.proto
