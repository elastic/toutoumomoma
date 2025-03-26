// Copyright ©2022 Elastic N.V. All rights reserved.
// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build requirefips

package toutoumomoma

import "fmt"

func (f *File) importHash() (hash []byte, imports []string, err error) {
	return nil, nil, fmt.Errorf("cannot generate md5 in fips mode: %w", ErrNotSupported)
}

func (f *File) goSymbolHash(stdlib bool) (hash []byte, imports []string, err error) {
	return nil, nil, fmt.Errorf("cannot generate md5 in fips mode: %w", ErrNotSupported)
}
