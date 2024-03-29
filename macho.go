// Copyright ©2022 Elastic N.V. All rights reserved.
// Copyright ©2021 Dan Kortschak. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package toutoumomoma

import (
	"debug/gosym"
	"io"
	"strings"

	"github.com/elastic/toutoumomoma/internal/macho"
)

type machoFile struct {
	r       io.ReaderAt
	objFile *macho.File
}

func openMachO(r io.ReaderAt) (*machoFile, error) {
	objFile, err := macho.NewFile(r)
	if err != nil {
		return nil, err
	}
	return &machoFile{r: r, objFile: objFile}, nil
}

func (f *machoFile) Close() error {
	f.objFile = nil
	if c, ok := f.r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

func (f *machoFile) isGoExecutable() (ok bool, err error) {
	for _, section := range f.objFile.Sections {
		switch section.Name {
		case "__gosymtab", "__gopclntab", "__go_buildinfo":
			return true, nil
		}
	}
	return false, nil
}

func (f *machoFile) hasBuildID() (ok bool, err error) {
	sect := f.objFile.Section("__go_buildinfo")
	if sect == nil {
		return false, nil
	}
	_, err = sect.Data()
	return err == nil, err
}

func (f *machoFile) hasRealFiles() (ok bool, err error) {
	tab, err := f.pclnTable()
	if err != nil {
		return false, err
	}
	if len(f.objFile.Symtab.Syms) == 0 {
		return false, nil
	}
	for _, sym := range f.objFile.Symtab.Syms {
		if sym.Name != "main.main" {
			continue
		}
		file, _, _ := tab.PCToLine(sym.Value)
		if file == "??" {
			return false, nil
		}
	}
	return true, nil
}

func (f *machoFile) importedSymbols() ([]string, error) {
	imports, err := f.objFile.ImportedSymbols()
	if err != nil {
		return nil, err
	}
	for i, imp := range imports {
		imports[i] = strings.ToLower(imp)
	}
	return imports, nil
}

func (f *machoFile) goSymbols(stdlib bool) ([]string, error) {
	tab, err := f.pclnTable()
	if err != nil {
		return nil, err
	}
	imports := make([]string, 0, len(f.objFile.Symtab.Syms))
	for _, sym := range f.objFile.Symtab.Syms {
		if sym.Sect == 0 || int(sym.Sect) > len(f.objFile.Sections) {
			continue
		}
		sect := f.objFile.Sections[sym.Sect-1]
		if sect.Seg != "__TEXT" || sect.Name != "__text" {
			continue
		}
		if strings.HasPrefix(sym.Name, "type..") {
			continue
		}
		if !stdlib && isStdlib(sym.Name, sym.Value, tab) {
			continue
		}
		imports = append(imports, sym.Name)
	}
	if len(imports) == 0 {
		imports = nil
	}
	return imports, nil
}

func (f *machoFile) pclnTable() (*gosym.Table, error) {
	textStart, symtab, pclntab, err := f.pcln()
	if err != nil {
		return nil, nil
	}
	return gosym.NewTable(symtab, gosym.NewLineTable(pclntab, textStart))
}

func (f *machoFile) sectionStats() ([]Section, error) {
	s := make([]Section, len(f.objFile.Sections))
	for i, sect := range f.objFile.Sections {
		h, sigma, err := streamEntropy(sect.Open())
		if err != nil {
			return nil, err
		}
		s[i] = Section{
			Name:       sect.Name,
			Size:       sect.Size,
			FileSize:   sect.Size,
			Entropy:    h,
			VarEntropy: sigma,
			Flags:      sect.Flags,
		}
	}
	return s, nil
}
