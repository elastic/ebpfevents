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

	"github.com/elastic/ebpfevents"
)

func main() {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	l, err := ebpfevents.NewLoader()
	if err != nil {
		log.Fatal(err)
	}
	log.Println("probes loaded!")

	events := make(chan ebpfevents.Event)
	errors := make(chan error)
	go l.EventLoop(context.Background(), events, errors)

	for {
		select {
		case err := <-errors:
			fmt.Printf("ERROR: %v\n", err)
			continue
		case ev := <-events:
			evj, err := json.Marshal(ev)
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
