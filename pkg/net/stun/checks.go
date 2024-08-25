// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package stun

import (
	"errors"
)

// CheckSize returns ErrAttrSizeInvalid if got is not equal to expected.
func CheckSize(_ AttrType, got, expected int) error {
	if got == expected {
		return nil
	}
	return ErrAttributeSizeInvalid
}

// IsAttrSizeInvalid returns true if error means that attribute size is invalid.
func IsAttrSizeInvalid(err error) bool {
	return errors.Is(err, ErrAttributeSizeInvalid)
}

// CheckOverflow returns ErrAttributeSizeOverflow if got is bigger that max.
func CheckOverflow(_ AttrType, got, maxVal int) error {
	if got <= maxVal {
		return nil
	}
	return ErrAttributeSizeOverflow
}

// IsAttrSizeOverflow returns true if error means that attribute size is too big.
func IsAttrSizeOverflow(err error) bool {
	return errors.Is(err, ErrAttributeSizeOverflow)
}
