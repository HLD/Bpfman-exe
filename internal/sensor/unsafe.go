package sensor

import "unsafe"

func unsafeBytes(p *uint32) unsafe.Pointer { return unsafe.Pointer(p) }
