// Copyright ©2022 Elastic N.V. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build go1.18
// +build go1.18

package macho

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func FuzzOpen(f *testing.F) {
	const (
		pkg     = "./testdata"
		objects = "./testdata/objects"
	)

	for _, seed := range [][]byte{
		{},
		{0},
		[]byte("\xfe\xed\xfa"),
		[]byte("\xfa\xed\xfe"),
	} {
		f.Add(seed)
	}

	obj, err := filepath.Glob(filepath.Join(objects, "*"))
	if err != nil {
		f.Fatalf("failed to get object glob: %v", err)
	}
	for _, path := range obj {
		b, err := os.ReadFile(path)
		if err != nil {
			f.Fatalf("failed to read object: %v", err)
		}
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, in []byte) {
		func() {
			f, err := NewFile(bytes.NewReader(in))
			if err != nil {
				t.Skip(err)
			}
			f.Close()
		}()
	})
}

func FuzzImportedSymbols(f *testing.F) {
	const (
		pkg     = "./testdata"
		objects = "./testdata/objects"
	)

	for _, seed := range [][]byte{
		{},
		{0},
		[]byte("\x7FELF"),
	} {
		f.Add(seed)
	}

	obj, err := filepath.Glob(filepath.Join(objects, "*"))
	if err != nil {
		f.Fatalf("failed to get object glob: %v", err)
	}
	for _, path := range obj {
		b, err := os.ReadFile(path)
		if err != nil {
			f.Fatalf("failed to read object: %v", err)
		}
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, in []byte) {
		func() {
			defer func() {
				r := recover()
				if r != nil {
					t.Skipf("panic during open: %v", r)
				}
			}()
			f, err := NewFile(bytes.NewReader(in))
			if err != nil {
				t.Skip(err)
			}
			f.ImportedSymbols()
			f.Close()
		}()
	})
}
