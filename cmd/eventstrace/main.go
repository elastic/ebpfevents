// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/elastic/ebpfevents"
)

func main() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	start := time.Now()
	l, err := ebpfevents.NewLoader()
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("probes loaded in %v!\n", time.Since(start))

	records := make(chan ebpfevents.Record, l.BufferLen())
	go l.EventLoop(context.Background(), records)

	for {
		select {
		case r := <-records:
			if r.Error != nil {
				fmt.Printf("ERROR: %v\n", r.Error)
				continue
			}

			evj, err := json.Marshal(r.Event)
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf("%v\n", string(evj))

			continue
		case <-stop:
			return
		}
	}
}
