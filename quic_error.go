// https://github.com/SagerNet/sing-quic/blob/3f28b3fc2f7d356c68befaffe02e3a8d0d2ef189/quic_error.go

package shadowquic

import (
	"errors"
	"io"
	"net"

	quic "github.com/metacubex/jls-quic-go"
)

type quicError struct {
	err error
}

func wrapQUICError(err error) error {
	if err == nil {
		return nil
	}
	if err == io.EOF {
		return io.EOF
	}
	return &quicError{err: err}
}

func (e *quicError) Error() string {
	return e.err.Error()
}

func (e *quicError) Unwrap() error {
	return e.err
}

func (e *quicError) Is(target error) bool {
	if errors.Is(e.err, target) {
		return true
	}
	switch target {
	case net.ErrClosed:
		var streamErr *quic.StreamError
		if errors.As(e.err, &streamErr) {
			return !streamErr.Remote && streamErr.ErrorCode == 0
		}
		var transportErr *quic.TransportError
		if errors.As(e.err, &transportErr) {
			return transportErr.ErrorCode == quic.NoError
		}
		var appErr *quic.ApplicationError
		if errors.As(e.err, &appErr) {
			return appErr.Remote && appErr.ErrorCode == 0
		}
	case io.EOF:
		var streamErr *quic.StreamError
		if errors.As(e.err, &streamErr) {
			return !streamErr.Remote && streamErr.ErrorCode == 0
		}
	}
	return false
}
