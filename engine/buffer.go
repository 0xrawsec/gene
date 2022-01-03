package engine

import (
	"errors"
	"io"
	"os"
)

var (
	errBufferOutOfBounds = errors.New("Seek buffer out of bound")
)

type seekBuffer struct {
	i    int
	buff []byte
}

func newSeekBuffer(b []byte) *seekBuffer {
	sb := &seekBuffer{}
	sb.buff = make([]byte, len(b))
	copy(sb.buff, b)
	return sb
}

func (sb *seekBuffer) Read(p []byte) (n int, err error) {
	if sb.i+len(p) < sb.Len() {
		n = copy(p, sb.buff[sb.i:sb.i+len(p)])
		sb.i += n
		return n, nil
	}
	n = copy(p, sb.buff[sb.i:])
	sb.i += n
	return n, io.EOF
}

func (sb *seekBuffer) Seek(offset int64, whence int) (int64, error) {
	switch whence {
	case os.SEEK_CUR:
		if sb.i+int(offset) <= sb.Len() {
			sb.i += int(offset)
			break
		}
		return 0, errBufferOutOfBounds
	case os.SEEK_SET:
		if int(offset) <= sb.Len() && offset >= 0 {
			sb.i = int(offset)
			break
		}
		return 0, errBufferOutOfBounds
	case os.SEEK_END:
		if sb.Len()-int(offset) > 0 {
			sb.i = sb.Len() - int(offset)
			break
		}
		return 0, errBufferOutOfBounds
	}
	return int64(sb.i), nil
}

func (sb *seekBuffer) Len() int {
	return len(sb.buff)
}
