// SPDX-License-Identifier: Apache-2.0

package difftest

import (
	"crypto/sha256"
	"math/big"

	bls "github.com/consensys/gnark-crypto/ecc/bls12-381"
	"github.com/consensys/gnark-crypto/ecc/bls12-381/fp"
)

// Random byte strings almost never decode to a point in the prime-order
// subgroup, so the point generators below build each encoding class
// deliberately and let the fuzzer choose among them.

var fieldP = fp.Modulus()

func scalarOf(data []byte) *big.Int {
	h := sha256.Sum256(data)
	return new(big.Int).SetBytes(h[:])
}

func fpOf(data []byte, salt byte) fp.Element {
	h := sha256.Sum256(append([]byte{salt}, data...))
	var e fp.Element
	e.SetBytes(h[:])
	return e
}

// addP adds the field modulus to the 381-bit big-endian field element at
// b[off:off+48] (flag bits of the first byte excluded) if the sum still
// fits, giving a non-canonical encoding of the same element.
func addP(b []byte, off int) {
	flags := b[off] & 0xe0
	x := new(big.Int).SetBytes(append([]byte{b[off] & 0x1f}, b[off+1:off+48]...))
	x.Add(x, fieldP)
	if x.BitLen() > 381 {
		return
	}
	x.FillBytes(b[off : off+48])
	b[off] |= flags
}

// G1Encoding returns a candidate compressed-G1 encoding of the class
// selected by mode, derived from data.
func G1Encoding(mode byte, data []byte) []byte {
	var g bls.G1Affine
	g.ScalarMultiplicationBase(scalarOf(data))
	valid := g.Bytes()
	switch mode % 9 {
	case 0:
		return clip(data, 200)
	case 1:
		return valid[:]
	case 2: // on the curve, almost surely outside the subgroup
		x := fpOf(data, 2)
		var four fp.Element
		four.SetUint64(4)
		for {
			var rhs, y fp.Element
			rhs.Square(&x).Mul(&rhs, &x).Add(&rhs, &four)
			if y.Sqrt(&rhs) != nil {
				p := bls.G1Affine{X: x, Y: y}
				b := p.Bytes()
				return b[:]
			}
			x.Add(&x, &four)
		}
	case 3: // x + p
		b := valid
		addP(b[:], 0)
		return b[:]
	case 4: // infinity flag with stray bits
		b := make([]byte, 48)
		b[0] = 0xc0
		if len(data) > 0 {
			b[0] |= data[0] & 0x3f
			copy(b[1:], data[1:])
		}
		return b
	case 5: // compression flag cleared
		b := valid
		b[0] &^= 0x80
		return b[:]
	case 6: // sort flag flipped: the negated point
		b := valid
		b[0] ^= 0x20
		return b[:]
	case 7: // uncompressed encoding, with flag variants
		r := g.RawBytes()
		if len(data) > 0 {
			r[0] |= data[0] & 0xe0
		}
		return r[:]
	default: // valid point, longer or shorter
		n := 48
		if len(data) > 0 {
			n = int(data[0]) % 100
		}
		return resize(valid[:], n, data)
	}
}

// G2Encoding is G1Encoding for compressed G2 keys (Fp2 x as c1 || c0).
func G2Encoding(mode byte, data []byte) []byte {
	var g bls.G2Affine
	g.ScalarMultiplicationBase(scalarOf(data))
	valid := g.Bytes()
	switch mode % 9 {
	case 0:
		return clip(data, 300)
	case 1:
		return valid[:]
	case 2:
		var x, b bls.E2
		x.A0, x.A1 = fpOf(data, 0), fpOf(data, 1)
		b.A0.SetUint64(4)
		b.A1.SetUint64(4)
		for {
			var rhs, y bls.E2
			rhs.Square(&x).Mul(&rhs, &x).Add(&rhs, &b)
			if rhs.Legendre() == 1 {
				y.Sqrt(&rhs)
				p := bls.G2Affine{X: x, Y: y}
				e := p.Bytes()
				return e[:]
			}
			x.A0.Add(&x.A0, &b.A0)
		}
	case 3: // c1 + p or c0 + p
		e := valid
		if len(data) > 0 && data[0]&1 == 1 {
			addP(e[:], 48)
		} else {
			addP(e[:], 0)
		}
		return e[:]
	case 4:
		e := make([]byte, 96)
		e[0] = 0xc0
		if len(data) > 0 {
			e[0] |= data[0] & 0x3f
			copy(e[1:], data[1:])
		}
		return e
	case 5:
		e := valid
		e[0] &^= 0x80
		return e[:]
	case 6:
		e := valid
		e[0] ^= 0x20
		return e[:]
	case 7:
		r := g.RawBytes()
		if len(data) > 0 {
			r[0] |= data[0] & 0xe0
		}
		return r[:]
	default:
		n := 96
		if len(data) > 0 {
			n = int(data[0]) % 200
		}
		return resize(valid[:], n, data)
	}
}

func clip(b []byte, n int) []byte {
	if len(b) > n {
		return b[:n]
	}
	return b
}

func resize(b []byte, n int, fill []byte) []byte {
	if n <= len(b) {
		return b[:n]
	}
	out := append([]byte(nil), b...)
	for len(out) < n {
		if len(fill) > 0 {
			out = append(out, fill[len(out)%len(fill)])
		} else {
			out = append(out, 0)
		}
	}
	return out
}

// PointRequest builds a sig_decode (G1) or vk_decode (G2) request.
func PointRequest(g2 bool, mode byte, data []byte) Request {
	if g2 {
		return Request{"op": "vk_decode", "b": hexOf(G2Encoding(mode, data))}
	}
	return Request{"op": "sig_decode", "b": hexOf(G1Encoding(mode, data))}
}
