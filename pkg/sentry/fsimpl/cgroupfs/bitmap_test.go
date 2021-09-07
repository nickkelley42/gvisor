// Copyright 2021 The gVisor Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package cgroupfs

import (
	"fmt"
	"reflect"
	"testing"

	"gvisor.dev/gvisor/pkg/bitmap"
)

func TestRender(t *testing.T) {
	tests := []struct {
		input  []uint32
		output string
	}{
		{[]uint32{1, 2, 3, 4, 7}, "1-4,7"},
		{[]uint32{2}, "2"},
		{[]uint32{0, 1, 2}, "0-2"},
		{[]uint32{}, ""},
		{[]uint32{1, 3, 4, 5, 6, 9, 11, 13, 14, 15, 16, 17}, "1,3-6,9,11,13-17"},
		{[]uint32{2, 3, 10, 12, 13, 14, 15, 16, 20, 21, 33, 34, 47}, "2-3,10,12-16,20-21,33-34,47"},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			b := bitmap.New(64)
			for _, v := range tt.input {
				b.Add(v)
			}
			s := formatBitmap(&b)
			if s != tt.output {
				t.Errorf("Expected %q, got %q", tt.output, s)
			}
		})
	}
}

func TestParse(t *testing.T) {
	tests := []struct {
		input  string
		output []uint32
	}{
		{"1", []uint32{1}},
		{"", []uint32{}},
		{"1-2,3,4,10,11", []uint32{1, 2, 3, 4, 10, 11}},
		{"1,2-4,5,16", []uint32{1, 2, 3, 4, 5, 16}},
	}
	for i, tt := range tests {
		t.Run(fmt.Sprintf("case-%d", i), func(t *testing.T) {
			b, err := parseBitmap(tt.input, 64)
			if err != nil {
				t.Errorf("Failed to parse bitmap: %v", err)
			}
			got := b.ToSlice()
			if !reflect.DeepEqual(got, tt.output) {
				t.Errorf("Parsed bitmap doesn't match what we expected. Got %v, want %v", got, tt.output)
			}

		})
	}
}
