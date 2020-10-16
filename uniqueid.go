package razproxy

import (
	"fmt"
	"time"

	"github.com/razzie/babble"
)

// UniqueID ...
func UniqueID() string {
	i := uint16(time.Now().UnixNano())
	babbler := babble.NewBabbler()
	return fmt.Sprintf("%s-%x", babbler.Babble(), i)
}
