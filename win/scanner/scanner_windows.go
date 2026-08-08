//go:build windows

package scanner

func raiseFdLimit() int {
	return -1
}