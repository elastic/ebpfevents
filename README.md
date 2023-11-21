## ebpfevents
[![Build status](https://badge.buildkite.com/41ffa4115fadaa3ec19e7ffa157bf0ac8020111ce3720625ed.svg)](https://buildkite.com/elastic/ebpfevents)

`ebpfevents` is a Go package for the Linux Kernel event sourcing using [eBPF](https://ebpf.io/). It consists of a Go loader using the [ebpf-go](https://github.com/cilium/ebpf) library and the eBPF probes defined in [elastic/ebpf](https://github.com/elastic/ebpf).

To try it: `go run -exec sudo ./cmd/eventstrace`
