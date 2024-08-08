package efw

import "golang.org/x/sys/windows"

func CloseHandles(hs []windows.Handle) error {
	var closeErr error
	for _, h := range hs {
		err := windows.CloseHandle(h)
		if err != nil && closeErr == nil {
			closeErr = err
		}
	}
	return closeErr
}
