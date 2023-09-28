## ebpfevents

`ebpfevents` is a Go package for the Linux Kernel event sourcing using [eBPF](https://ebpf.io/). It consists of a Go loader using the [ebpf-go](https://github.com/cilium/ebpf) library and the eBPF probes defined in [elastic/ebpf](https://github.com/elastic/ebpf).

To try it:
- `CLANG=clang make generate`
- `CLANG=clang make build-eventstrace`
- `go run -exec sudo ./cmd/eventstrace`
