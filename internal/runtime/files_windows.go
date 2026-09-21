package runtime

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/windows"
)

func resolveTrustedDirectory(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return "", errors.New("managed data root must be a directory")
	}
	buffer := make([]uint16, 1024)
	for {
		n, err := windows.GetFinalPathNameByHandle(windows.Handle(file.Fd()), &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return "", err
		}
		if n >= uint32(len(buffer)) {
			buffer = make([]uint16, n+1)
			continue
		}
		final := windows.UTF16ToString(buffer[:n])
		if strings.HasPrefix(final, `\\?\UNC\`) {
			return `\\` + strings.TrimPrefix(final, `\\?\UNC\`), nil
		}
		return strings.TrimPrefix(final, `\\?\`), nil
	}
}
