//go:build !go1.21

package auxv

func runtime_getAuxv() []uintptr { return nil }
