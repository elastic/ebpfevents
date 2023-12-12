# ebpfevents
[![Build status](https://badge.buildkite.com/41ffa4115fadaa3ec19e7ffa157bf0ac8020111ce3720625ed.svg)](https://buildkite.com/elastic/ebpfevents)

`ebpfevents` is a Go package for the Linux Kernel event sourcing using [eBPF](https://ebpf.io/). It consists of a Go loader using the [ebpf-go](https://github.com/cilium/ebpf) library and the eBPF probes defined in [elastic/ebpf](https://github.com/elastic/ebpf).

## Quick Start

To try ebpfevents, run: `go run -exec sudo ./cmd/eventstrace`

## License

This software is licensed under the Apache License, version 2 ("ALv2"), quoted below.

Copyright 2023-2023 Elasticsearch <https://www.elastic.co>

Licensed under the Apache License, Version 2.0 (the "License"); you may not
use this file except in compliance with the License. You may obtain a copy of
the License at

> http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
License for the specific language governing permissions and limitations under
the License.

This repository includes dependencies/submodules whose licenses are listed in [LICENSE.txt](LICENSE.txt).
