//go:build !windows

package scanner

import "syscall"

func raiseFdLimit() int {
	var rl syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return -1
	}
	rl.Cur = rl.Max
	if err := syscall.Setrlimit(syscall.RLIMIT_NOFILE, &rl); err != nil {
		return -1
	}
	var cur syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &cur); err != nil {
		return -1
	}
	return int(cur.Cur)
}