// Copyright ©2022 Elastic N.V. All rights reserved.
// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !requirefips

package toutoumomoma

import (
	"crypto/md5"
	"fmt"
)

func (f *File) importHash() (hash []byte, imports []string, err error) {
	// Algorithm from https://www.fireeye.com/blog/threat-research/2014/01/tracking-malware-import-hashing.html
	//  - Resolving ordinals to function names when they appear (done by the debug/pe library)
	//  - Converting both DLL names and function names to all lowercase
	//  - Removing the file extensions from imported module names
	//  - Building and storing the lowercased string in an ordered list
	//  - Generating the MD5 hash of the ordered list
	//
	// The algorithm is generalised to non-Windows platforms as described in
	// the doc comment.
	imports, err = f.Imports()
	if err != nil {
		return nil, nil, err
	}

	h := md5.New()
	if len(imports) == 0 {
		return h.Sum(nil), nil, nil
	}
	for i, imp := range imports {
		if i != 0 {
			_, _ = h.Write([]byte{','})
		}
		fmt.Fprint(h, imp)
	}
	return h.Sum(nil), imports, nil
}

func (f *File) goSymbolHash(stdlib bool) (hash []byte, imports []string, err error) {
	ok, err := f.isGoExecutable()
	if !ok || err != nil {
		if err != nil {
			return nil, nil, err
		}
		return nil, nil, ErrNotGoExecutable
	}

	imports, err = f.goSymbols(stdlib)
	if err != nil {
		return nil, nil, err
	}
	h := md5.New()
	if len(imports) == 0 {
		return h.Sum(nil), nil, nil
	}
	for i, imp := range imports {
		if i != 0 {
			_, _ = h.Write([]byte{','})
		}
		fmt.Fprint(h, imp)
	}
	return h.Sum(nil), imports, nil
}
