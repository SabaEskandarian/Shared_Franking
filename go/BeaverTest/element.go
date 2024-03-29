// Copyright 2020 ConsenSys Software Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by goff (v0.3.6) DO NOT EDIT

// Package modp contains field arithmetic operations for modulus 340282366920938463463374607431768211297
package main

// /!\ WARNING /!\
// this code has not been audited and is provided as-is. In particular,
// there is no security guarantees such as constant time implementation
// or side-channel attack resistance
// /!\ WARNING /!\

import (
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"
	"math/bits"
	"strconv"
	"sync"
)

// Element represents a field element stored on 2 words (uint64)
// Element are assumed to be in Montgomery form in all methods
// field modulus q =
//
// 340282366920938463463374607431768211297
type Element [2]uint64

// Limbs number of 64 bits words needed to represent Element
const Limbs = 2

// Bits number bits needed to represent Element
const Bits = 128

// field modulus stored as big.Int
var _modulus big.Int
var onceModulus sync.Once

// Modulus returns q as a big.Int
// q =
//
// 340282366920938463463374607431768211297
func Modulus() *big.Int {
	onceModulus.Do(func() {
		_modulus.SetString("340282366920938463463374607431768211297", 10)
	})
	return new(big.Int).Set(&_modulus)
}

// q (modulus)
var qElement = Element{
	18446744073709551457,
	18446744073709551615,
}

// rSquare
var rSquare = Element{
	25281,
	0,
}

// Bytes returns the regular (non montgomery) value
// of z as a big-endian byte slice.
func (z *Element) Bytes() []byte {
	_z := z.ToRegular()
	var res [Limbs * 8]byte
	binary.BigEndian.PutUint64(res[8:16], _z[0])
	binary.BigEndian.PutUint64(res[0:8], _z[1])

	return res[:]
}

// SetBytes interprets e as the bytes of a big-endian unsigned integer,
// sets z to that value (in Montgomery form), and returns z.
func (z *Element) SetBytes(e []byte) *Element {
	var tmp big.Int
	tmp.SetBytes(e)
	z.SetBigInt(&tmp)
	return z
}

// SetUint64 z = v, sets z LSB to v (non-Montgomery form) and convert z to Montgomery form
func (z *Element) SetUint64(v uint64) *Element {
	*z = Element{v}
	return z.Mul(z, &rSquare) // z.ToMont()
}

// Set z = x
func (z *Element) Set(x *Element) *Element {
	z[0] = x[0]
	z[1] = x[1]
	return z
}

// SetInterface converts i1 from uint64, int, string, or Element, big.Int into Element
// panic if provided type is not supported
func (z *Element) SetInterface(i1 interface{}) *Element {
	switch c1 := i1.(type) {
	case Element:
		return z.Set(&c1)
	case *Element:
		return z.Set(c1)
	case uint64:
		return z.SetUint64(c1)
	case int:
		return z.SetString(strconv.Itoa(c1))
	case string:
		return z.SetString(c1)
	case *big.Int:
		return z.SetBigInt(c1)
	case big.Int:
		return z.SetBigInt(&c1)
	case []byte:
		return z.SetBytes(c1)
	default:
		panic("invalid type")
	}
}

// SetZero z = 0
func (z *Element) SetZero() *Element {
	z[0] = 0
	z[1] = 0
	return z
}

// SetOne z = 1 (in Montgomery form)
func (z *Element) SetOne() *Element {
	z[0] = 159
	z[1] = 0
	return z
}

// Div z = x*y^-1 mod q
func (z *Element) Div(x, y *Element) *Element {
	var yInv Element
	yInv.Inverse(y)
	z.Mul(x, &yInv)
	return z
}

// Equal returns z == x
func (z *Element) Equal(x *Element) bool {
	return (z[1] == x[1]) && (z[0] == x[0])
}

// IsZero returns z == 0
func (z *Element) IsZero() bool {
	return (z[1] | z[0]) == 0
}

// SetRandom sets z to a random element < q
func (z *Element) SetRandom() *Element {
	bytes := make([]byte, 16)
	io.ReadFull(rand.Reader, bytes)
	z[0] = binary.BigEndian.Uint64(bytes[0:8])
	z[1] = binary.BigEndian.Uint64(bytes[8:16])
	z[1] %= 18446744073709551615

	// if z > q --> z -= q
	// note: this is NOT constant time
	if !(z[1] < 18446744073709551615 || (z[1] == 18446744073709551615 && (z[0] < 18446744073709551457))) {
		var b uint64
		z[0], b = bits.Sub64(z[0], 18446744073709551457, 0)
		z[1], _ = bits.Sub64(z[1], 18446744073709551615, b)
	}

	return z
}

// One returns 1 (in montgommery form)
func One() Element {
	var one Element
	one.SetOne()
	return one
}

// MulAssign is deprecated
// Deprecated: use Mul instead
func (z *Element) MulAssign(x *Element) *Element {
	return z.Mul(z, x)
}

// AddAssign is deprecated
// Deprecated: use Add instead
func (z *Element) AddAssign(x *Element) *Element {
	return z.Add(z, x)
}

// SubAssign is deprecated
// Deprecated: use Sub instead
func (z *Element) SubAssign(x *Element) *Element {
	return z.Sub(z, x)
}

// API with assembly impl

// Mul z = x * y mod q
// see https://hackmd.io/@zkteam/modular_multiplication
func (z *Element) Mul(x, y *Element) *Element {
	mul(z, x, y)
	return z
}

// Square z = x * x mod q
// see https://hackmd.io/@zkteam/modular_multiplication
func (z *Element) Square(x *Element) *Element {
	square(z, x)
	return z
}

// FromMont converts z in place (i.e. mutates) from Montgomery to regular representation
// sets and returns z = z * 1
func (z *Element) FromMont() *Element {
	fromMont(z)
	return z
}

// Add z = x + y mod q
func (z *Element) Add(x, y *Element) *Element {
	add(z, x, y)
	return z
}

// Double z = x + x mod q, aka Lsh 1
func (z *Element) Double(x *Element) *Element {
	double(z, x)
	return z
}

// Sub  z = x - y mod q
func (z *Element) Sub(x, y *Element) *Element {
	sub(z, x, y)
	return z
}

// Neg z = q - x
func (z *Element) Neg(x *Element) *Element {
	neg(z, x)
	return z
}

// Generic (no ADX instructions, no AMD64) versions of multiplication and squaring algorithms

func _mulGeneric(z, x, y *Element) {

	var t [3]uint64
	var D uint64
	var m, C uint64
	// -----------------------------------
	// First loop

	C, t[0] = bits.Mul64(y[0], x[0])
	C, t[1] = madd1(y[0], x[1], C)

	D = C

	// m = t[0]n'[0] mod W
	m = t[0] * 13109950190749555551

	// -----------------------------------
	// Second loop
	C = madd0(m, 18446744073709551457, t[0])

	C, t[0] = madd3(m, 18446744073709551615, t[1], C, t[2])

	t[1], t[2] = bits.Add64(D, C, 0)
	// -----------------------------------
	// First loop

	C, t[0] = madd1(y[1], x[0], t[0])
	C, t[1] = madd2(y[1], x[1], t[1], C)

	D = C

	// m = t[0]n'[0] mod W
	m = t[0] * 13109950190749555551

	// -----------------------------------
	// Second loop
	C = madd0(m, 18446744073709551457, t[0])

	C, t[0] = madd3(m, 18446744073709551615, t[1], C, t[2])

	t[1], t[2] = bits.Add64(D, C, 0)

	if t[2] != 0 {
		// we need to reduce, we have a result on 3 words
		var b uint64
		z[0], b = bits.Sub64(t[0], 18446744073709551457, 0)
		z[1], _ = bits.Sub64(t[1], 18446744073709551615, b)

		return

	}

	// copy t into z
	z[0] = t[0]
	z[1] = t[1]

	// if z > q --> z -= q
	// note: this is NOT constant time
	if !(z[1] < 18446744073709551615 || (z[1] == 18446744073709551615 && (z[0] < 18446744073709551457))) {
		var b uint64
		z[0], b = bits.Sub64(z[0], 18446744073709551457, 0)
		z[1], _ = bits.Sub64(z[1], 18446744073709551615, b)
	}
}

func _squareGeneric(z, x *Element) {

	var t [3]uint64
	var D uint64
	var m, C uint64
	// -----------------------------------
	// First loop

	C, t[0] = bits.Mul64(x[0], x[0])
	C, t[1] = madd1(x[0], x[1], C)

	D = C

	// m = t[0]n'[0] mod W
	m = t[0] * 13109950190749555551

	// -----------------------------------
	// Second loop
	C = madd0(m, 18446744073709551457, t[0])

	C, t[0] = madd3(m, 18446744073709551615, t[1], C, t[2])

	t[1], t[2] = bits.Add64(D, C, 0)
	// -----------------------------------
	// First loop

	C, t[0] = madd1(x[1], x[0], t[0])
	C, t[1] = madd2(x[1], x[1], t[1], C)

	D = C

	// m = t[0]n'[0] mod W
	m = t[0] * 13109950190749555551

	// -----------------------------------
	// Second loop
	C = madd0(m, 18446744073709551457, t[0])

	C, t[0] = madd3(m, 18446744073709551615, t[1], C, t[2])

	t[1], t[2] = bits.Add64(D, C, 0)

	if t[2] != 0 {
		// we need to reduce, we have a result on 3 words
		var b uint64
		z[0], b = bits.Sub64(t[0], 18446744073709551457, 0)
		z[1], _ = bits.Sub64(t[1], 18446744073709551615, b)

		return

	}

	// copy t into z
	z[0] = t[0]
	z[1] = t[1]

	// if z > q --> z -= q
	// note: this is NOT constant time
	if !(z[1] < 18446744073709551615 || (z[1] == 18446744073709551615 && (z[0] < 18446744073709551457))) {
		var b uint64
		z[0], b = bits.Sub64(z[0], 18446744073709551457, 0)
		z[1], _ = bits.Sub64(z[1], 18446744073709551615, b)
	}
}

func _fromMontGeneric(z *Element) {
	// the following lines implement z = z * 1
	// with a modified CIOS montgomery multiplication
	{
		// m = z[0]n'[0] mod W
		m := z[0] * 13109950190749555551
		C := madd0(m, 18446744073709551457, z[0])
		C, z[0] = madd2(m, 18446744073709551615, z[1], C)
		z[1] = C
	}
	{
		// m = z[0]n'[0] mod W
		m := z[0] * 13109950190749555551
		C := madd0(m, 18446744073709551457, z[0])
		C, z[0] = madd2(m, 18446744073709551615, z[1], C)
		z[1] = C
	}

	// if z > q --> z -= q
	// note: this is NOT constant time
	if !(z[1] < 18446744073709551615 || (z[1] == 18446744073709551615 && (z[0] < 18446744073709551457))) {
		var b uint64
		z[0], b = bits.Sub64(z[0], 18446744073709551457, 0)
		z[1], _ = bits.Sub64(z[1], 18446744073709551615, b)
	}
}

// Exp z = x^exponent mod q
func (z *Element) Exp(x Element, exponent *big.Int) *Element {
	var bZero big.Int
	if exponent.Cmp(&bZero) == 0 {
		return z.SetOne()
	}

	z.Set(&x)

	for i := exponent.BitLen() - 2; i >= 0; i-- {
		z.Square(z)
		if exponent.Bit(i) == 1 {
			z.Mul(z, &x)
		}
	}

	return z
}

// ToMont converts z to Montgomery form
// sets and returns z = z * r^2
func (z *Element) ToMont() *Element {
	return z.Mul(z, &rSquare)
}

// ToRegular returns z in regular form (doesn't mutate z)
func (z Element) ToRegular() Element {
	return *z.FromMont()
}

// String returns the string form of an Element in Montgomery form
func (z *Element) String() string {
	var _z big.Int
	return z.ToBigIntRegular(&_z).String()
}

// ToBigInt returns z as a big.Int in Montgomery form
func (z *Element) ToBigInt(res *big.Int) *big.Int {
	var b [Limbs * 8]byte
	binary.BigEndian.PutUint64(b[8:16], z[0])
	binary.BigEndian.PutUint64(b[0:8], z[1])

	return res.SetBytes(b[:])
}

// ToBigIntRegular returns z as a big.Int in regular form
func (z Element) ToBigIntRegular(res *big.Int) *big.Int {
	z.FromMont()
	return z.ToBigInt(res)
}

// SetBigInt sets z to v (regular form) and returns z in Montgomery form
func (z *Element) SetBigInt(v *big.Int) *Element {
	z.SetZero()

	var zero big.Int
	q := Modulus()

	// fast path
	c := v.Cmp(q)
	if c == 0 {
		// v == 0
		return z
	} else if c != 1 && v.Cmp(&zero) != -1 {
		// 0 < v < q
		return z.setBigInt(v)
	}

	// copy input + modular reduction
	vv := new(big.Int).Set(v)
	vv.Mod(v, q)

	return z.setBigInt(vv)
}

// setBigInt assumes 0 <= v < q
func (z *Element) setBigInt(v *big.Int) *Element {
	vBits := v.Bits()

	if bits.UintSize == 64 {
		for i := 0; i < len(vBits); i++ {
			z[i] = uint64(vBits[i])
		}
	} else {
		for i := 0; i < len(vBits); i++ {
			if i%2 == 0 {
				z[i/2] = uint64(vBits[i])
			} else {
				z[i/2] |= uint64(vBits[i]) << 32
			}
		}
	}

	return z.ToMont()
}

// SetString creates a big.Int with s (in base 10) and calls SetBigInt on z
func (z *Element) SetString(s string) *Element {
	x, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("Element.SetString failed -> can't parse number in base10 into a big.Int")
	}
	return z.SetBigInt(x)
}

var (
	_bLegendreExponentElement *big.Int
	_bSqrtExponentElement     *big.Int
)

func init() {
	_bLegendreExponentElement, _ = new(big.Int).SetString("7fffffffffffffffffffffffffffffb0", 16)
	const sqrtExponentElement = "3fffffffffffffffffffffffffffffd"
	_bSqrtExponentElement, _ = new(big.Int).SetString(sqrtExponentElement, 16)
}

// Legendre returns the Legendre symbol of z (either +1, -1, or 0.)
func (z *Element) Legendre() int {
	var l Element
	// z^((q-1)/2)
	l.Exp(*z, _bLegendreExponentElement)

	if l.IsZero() {
		return 0
	}

	// if l == 1
	if (l[1] == 0) && (l[0] == 159) {
		return 1
	}
	return -1
}

// Sqrt z = √x mod q
// if the square root doesn't exist (x is not a square mod q)
// Sqrt leaves z unchanged and returns nil
func (z *Element) Sqrt(x *Element) *Element {
	// q ≡ 1 (mod 4)
	// see modSqrtTonelliShanks in math/big/int.go
	// using https://www.maa.org/sites/default/files/pdf/upload_library/22/Polya/07468342.di020786.02p0470a.pdf

	var y, b, t, w Element
	// w = x^((s-1)/2))
	w.Exp(*x, _bSqrtExponentElement)

	// y = x^((s+1)/2)) = w * x
	y.Mul(x, &w)

	// b = x^s = w * w * x = y * x
	b.Mul(&w, &y)

	// g = nonResidue ^ s
	var g = Element{
		976913684368095672,
		17880663354656517912,
	}
	r := uint64(5)

	// compute legendre symbol
	// t = x^((q-1)/2) = r-1 squaring of x^s
	t = b
	for i := uint64(0); i < r-1; i++ {
		t.Square(&t)
	}
	if t.IsZero() {
		return z.SetZero()
	}
	if !((t[1] == 0) && (t[0] == 159)) {
		// t != 1, we don't have a square root
		return nil
	}
	for {
		var m uint64
		t = b

		// for t != 1
		for !((t[1] == 0) && (t[0] == 159)) {
			t.Square(&t)
			m++
		}

		if m == 0 {
			return z.Set(&y)
		}
		// t = g^(2^(r-m-1)) mod q
		ge := int(r - m - 1)
		t = g
		for ge > 0 {
			t.Square(&t)
			ge--
		}

		g.Square(&t)
		y.Mul(&y, &t)
		b.Mul(&b, &g)
		r = m
	}
}

// Inverse z = x^-1 mod q
// note: allocates a big.Int (math/big)
func (z *Element) Inverse(x *Element) *Element {
	var _xNonMont big.Int
	x.ToBigIntRegular(&_xNonMont)
	_xNonMont.ModInverse(&_xNonMont, Modulus())
	z.SetBigInt(&_xNonMont)
	return z
}
