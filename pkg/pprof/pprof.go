package pprof

// func MergePgoTo(files []string, to string) error {
// 	ps, err := Merge(files)
// 	if err != nil {
// 		return err
// 	}

// 	buf := pool.NewBuffer(nil)

// 	err = ps.Write(buf)
// 	if err != nil {
// 		return err
// 	}

// 	return os.WriteFile(to, buf.Bytes(), 0644)
// }

// func Merge(files []string) (*profile.Profile, error) {
// 	profiles := []*profile.Profile{}
// 	for _, file := range files {
// 		data, err := os.ReadFile(file)
// 		if err != nil {
// 			continue
// 		}

// 		ps, err := profile.ParseData(data)
// 		if err != nil {
// 			continue
// 		}

// 		profiles = append(profiles, ps)
// 	}

// 	if err := profile.CompatibilizeSampleTypes(profiles); err != nil {
// 		return nil, err
// 	}

// 	p, err := profile.Merge(profiles)
// 	if err != nil {
// 		return nil, err
// 	}

// 	_ = p.RemoveUninteresting()
// 	Demangle(p)
// 	return p, nil
// }

// // Demangle updates the function names in a profile with demangled C++
// // names, simplified according to demanglerMode. If force is set,
// // overwrite any names that appear already demangled.
// func Demangle(prof *profile.Profile) {
// 	for _, fn := range prof.Function {
// 		demangleSingleFunction(fn)
// 	}
// }

// func demangleSingleFunction(fn *profile.Function) {
// 	if fn.Name != "" && fn.SystemName != fn.Name {
// 		return // Already demangled.
// 	}
// 	/*
// 		* current we not use cgo, so just comment

// 		// Copy the options because they may be updated by the call.
// 		o := make([]demangle.Option, len(options))
// 		copy(o, options)
// 		if demangled := demangle.Filter(fn.SystemName, o...); demangled != fn.SystemName {
// 			fn.Name = demangled
// 			return
// 		}
// 	*/
// 	// Could not demangle. Apply heuristics in case the name is
// 	// already demangled.
// 	name := fn.SystemName
// 	if looksLikeDemangledCPlusPlus(name) {
// 		name = removeMatching(name, '(', ')')
// 		name = removeMatching(name, '<', '>')
// 	}
// 	fn.Name = name
// }

// // looksLikeDemangledCPlusPlus is a heuristic to decide if a name is
// // the result of demangling C++. If so, further heuristics will be
// // applied to simplify the name.
// func looksLikeDemangledCPlusPlus(demangled string) bool {
// 	// Skip java names of the form "class.<init>".
// 	if strings.Contains(demangled, ".<") {
// 		return false
// 	}
// 	// Skip Go names of the form "foo.(*Bar[...]).Method".
// 	if strings.Contains(demangled, "]).") {
// 		return false
// 	}
// 	return strings.ContainsAny(demangled, "<>[]") || strings.Contains(demangled, "::")
// }

// // removeMatching removes nested instances of start..end from name.
// func removeMatching(name string, start, end byte) string {
// 	s := string(start) + string(end)
// 	var nesting, first, current int
// 	for index := strings.IndexAny(name[current:], s); index != -1; index = strings.IndexAny(name[current:], s) {
// 		switch current += index; name[current] {
// 		case start:
// 			nesting++
// 			if nesting == 1 {
// 				first = current
// 			}
// 		case end:
// 			nesting--
// 			switch {
// 			case nesting < 0:
// 				return name // Mismatch, abort
// 			case nesting == 0:
// 				name = name[:first] + name[current+1:]
// 				current = first - 1
// 			}
// 		}
// 		current++
// 	}
// 	return name
// }
