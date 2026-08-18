//go:build !windows

package main

import "github.com/dop251/goja"

// registerWindowsHelpers provides stub implementations on non-Windows.
func registerWindowsHelpers(vm *goja.Runtime) {
	vm.Set("winIsMutexExist", func(name string) bool {
		_ = name
		return false
	})
	vm.Set("winIsServicePresent", func(name string) map[string]interface{} {
		return map[string]interface{}{"present": false, "error": "not implemented"}
	})
	vm.Set("winIsDriverPresent", func(name string) map[string]interface{} {
		return map[string]interface{}{"present": false, "error": "not implemented"}
	})
	vm.Set("winCheckNamedPipe", func(name string) map[string]interface{} {
		return map[string]interface{}{"exists": false, "error": "not implemented"}
	})
	vm.Set("winFileVersionInfo", func(path string) map[string]interface{} {
		return map[string]interface{}{"error": "not implemented"}
	})
	vm.Set("winSigInfo", func(path string) map[string]interface{} {
		return map[string]interface{}{"signed": false, "error": "not implemented"}
	})
}

func winSigInfoWintrust(path string) map[string]interface{} {
	return map[string]interface{}{"signed": false, "error": "not implemented"}
}
