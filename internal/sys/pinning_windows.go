package sys

import (
	"errors"
	"math"
	"os"
	"runtime"
)

func Pin(currentPath, newPath string, fd *FD) error {
	defer runtime.KeepAlive(fd)

	if newPath == "" {
		return errors.New("given pinning path cannot be empty")
	}
	if currentPath == newPath {
		return nil
	}

	if currentPath == "" {
		return ObjPin(&ObjPinAttr{
			Pathname: NewStringPointer(newPath),
			BpfFd:    fd.Uint(),
		})
	}

	return ObjPin(&ObjPinAttr{
		Pathname: NewStringPointer(newPath),
		BpfFd:    fd.Uint(),
	})
}

func Unpin(pinnedPath string) error {
	if pinnedPath == "" {
		return nil
	}

	err := ObjPin(&ObjPinAttr{
		Pathname: NewStringPointer(pinnedPath),
		BpfFd:    math.MaxUint32, // TODO: This is supposed to be windows.InvalidHandle.
	})
	// TODO: Check that IsNotExist actually makes sense here.
	if err == nil || os.IsNotExist(err) {
		return nil
	}
	return err
}
