package rome

// Pad will add padding to the left
func Pad(x []byte, size int) []byte {
	if len(x) >= size {
		return x
	}

	// pad with blank zeros
	blank := make([]byte, size-len(x))
	return append(blank, x...)
}
