package ebpf

import (
	"fmt"
	"reflect"
)

// LoadAndAssign loads Maps and Programs into the kernel and assigns them
// to a struct.
//
// Omitting Map/Program.Close() during application shutdown is an error.
// See the package documentation for details around Map and Program lifecycle.
//
// This function is a shortcut to manually checking the presence
// of maps and programs in a CollectionSpec. Consider using bpf2go
// if this sounds useful.
//
// 'to' must be a pointer to a struct. A field of the struct is updated with
// a Program or Map if it has an `ebpf` tag and its type is *Program or *Map.
// The tag's value specifies the name of the program or map as found in the
// CollectionSpec. Before updating the struct, the requested objects and their
// dependent resources are loaded into the kernel and populated with values if
// specified.
//
//	struct {
//	    Foo     *ebpf.Program `ebpf:"xdp_foo"`
//	    Bar     *ebpf.Map     `ebpf:"bar_map"`
//	    Ignored int
//	}
//
// opts may be nil.
//
// Returns an error if any of the fields can't be found, or
// if the same Map or Program is assigned multiple times.
func (cs *CollectionSpec) LoadAndAssign(to interface{}, opts *CollectionOptions) error {
	loader, err := newCollectionLoader(cs, opts)
	if err != nil {
		return err
	}
	defer loader.close()

	// Support assigning Programs and Maps, lazy-loading the required objects.
	assignedMaps := make(map[string]bool)
	assignedProgs := make(map[string]bool)

	getValue := func(typ reflect.Type, name string) (interface{}, error) {
		switch typ {

		case reflect.TypeOf((*Program)(nil)):
			assignedProgs[name] = true
			return loader.loadProgram(name)

		case reflect.TypeOf((*Map)(nil)):
			assignedMaps[name] = true
			return loader.loadMap(name)

		default:
			return nil, fmt.Errorf("unsupported type %s", typ)
		}
	}

	// Load the Maps and Programs requested by the annotated struct.
	if err := assignValues(to, getValue); err != nil {
		return err
	}

	// Populate the requested maps. Has a chance of lazy-loading other dependent maps.
	if err := loader.populateDeferredMaps(); err != nil {
		return err
	}

	// Evaluate the loader's objects after all (lazy)loading has taken place.
	for n, m := range loader.maps {
		switch m.typ {
		case ProgramArray:
			// Require all lazy-loaded ProgramArrays to be assigned to the given object.
			// The kernel empties a ProgramArray once the last user space reference
			// to it closes, which leads to failed tail calls. Combined with the library
			// closing map fds via GC finalizers this can lead to surprising behaviour.
			// Only allow unassigned ProgramArrays when the library hasn't pre-populated
			// any entries from static value declarations. At this point, we know the map
			// is empty and there's no way for the caller to interact with the map going
			// forward.
			if !assignedMaps[n] && len(cs.Maps[n].Contents) > 0 {
				return fmt.Errorf("ProgramArray %s must be assigned to prevent missed tail calls", n)
			}
		}
	}

	// Prevent loader.cleanup() from closing assigned Maps and Programs.
	for m := range assignedMaps {
		delete(loader.maps, m)
	}
	for p := range assignedProgs {
		delete(loader.programs, p)
	}

	return nil
}

// NewCollection creates a Collection from the given spec, creating and
// loading its declared resources into the kernel.
//
// Omitting Collection.Close() during application shutdown is an error.
// See the package documentation for details around Map and Program lifecycle.
func NewCollection(spec *CollectionSpec) (*Collection, error) {
	return NewCollectionWithOptions(spec, CollectionOptions{})
}

// LoadCollection reads an object file and creates and loads its declared
// resources into the kernel.
//
// Omitting Collection.Close() during application shutdown is an error.
// See the package documentation for details around Map and Program lifecycle.
func LoadCollection(file string) (*Collection, error) {
	spec, err := LoadCollectionSpec(file)
	if err != nil {
		return nil, err
	}
	return NewCollection(spec)
}
