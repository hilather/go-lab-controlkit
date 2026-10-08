package multiline

import "testing"

func FuzzMulti(
	f *testing.F, // fuzz handle
) {
}

func FuzzOne(f *testing.F) {}

func Helper(f *testing.F) {}

func FuzzWrong(f *testing.T) {}
