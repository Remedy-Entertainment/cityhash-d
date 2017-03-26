// Copyright (c) 2011 Google, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
// CityHash, by Geoff Pike and Jyrki Alakuijala
// CityHash-D, port to the D language by Ethan Watson
//
// https://github.com/google/cityhash/
//
// This file provides a few functions for hashing strings.  All of them are
// high-quality functions in the sense that they pass standard tests such
// as Austin Appleby's SMHasher.  They are also fast.
//
// For 64-bit x86 code, on short strings, we don't know of anything faster than
// CityHash64 that is of comparable quality.  We believe our nearest competitor
// is Murmur3.  For 64-bit x86 code, CityHash64 is an excellent choice for hash
// tables and most other hashing (excluding cryptography).
//
// For 64-bit x86 code, on long strings, the picture is more complicated.
// On many recent Intel CPUs, such as Nehalem, Westmere, Sandy Bridge, etc.,
// CityHashCrc128 appears to be faster than all competitors of comparable
// quality.  CityHash128 is also good but not quite as fast.  We believe our
// nearest competitor is Bob Jenkins' Spooky.  We don't have great data for
// other 64-bit CPUs, but for long strings we know that Spooky is slightly
// faster than CityHash on some relatively recent AMD x86-64 CPUs, for example.
// Note that CityHashCrc128 is declared in citycrc.h.
//
// For 32-bit x86 code, we don't know of anything faster than CityHash32 that
// is of comparable quality.  We believe our nearest competitor is Murmur3A.
// (On 64-bit CPUs, it is typically faster to use the other CityHash variants.)
//
// Functions in the CityHash family are not suitable for cryptography.
//
// Please see CityHash's README file for more details on our performance
// measurements and so on.
//
// WARNING: This code has been only lightly tested on big-endian platforms!
// It is known to work well on little-endian platforms that have a small penalty
// for unaligned reads, such as current Intel and AMD moderate-to-high-end CPUs.
// It should work on all 32-bit and 64-bit platforms that allow unaligned reads;
// bug reports are welcome.
//
// By the way, for some hash functions, given strings a and b, the hash
// of a+b is easily derived from the hashes of a and b.  This property
// doesn't hold for any hash functions in this file.
//
// Notes for D users:
//
// You should import this module if you wish to use CityHash. The implementations
// for 32- and 64-bit logic live in their own modules, while common functionality
// to both live in this module.
//
// This implementation of CityHash is fully CTFE compliant. As such, it may not
// be as performant at runtime as the native C++ implementation. Future versions
// of this code will branch for CTFE and runtime versions, and thus should be
// near to the same performance as the C++ version.

module cityhash.cityhash;

public import cityhash.cityhash32;
public import cityhash.cityhash64 : CityHash64, CityHash64WithSeed, CityHash64WithSeeds;

// Implementation follows
package:

// Some primes between 2^63 and 2^64 for various uses.
enum ulong k0 = 0xc3a5c85c97cb3127L;
enum ulong k1 = 0xb492b66fbe98f273L;
enum ulong k2 = 0x9ae16a3b2f90404fL;

// Magic numbers for 32-bit hashing.  Copied from Murmur3.
enum uint c1 = 0xcc9e2d51;
enum uint c2 = 0x1b873593;

struct Pair( T1, T2 )
{
	T1 first;
	T2 second;
}

auto Rotate( T )( T val, T shift )
{
	enum T MaxBits = T.sizeof << 3;

	return shift == 0 ? val : ( ( val >> shift ) | ( val << ( MaxBits - shift ) ) );
}

void Swap( T )( ref T val1, ref T val2 )
{
	T tmp = val1;
	val1 = val2;
	val2 = tmp;
}

auto ByteSwap( T )( T val )
{
	static if( is( T == char ) || is( T == byte ) || is( T == ubyte ) )
	{
		return val;
	}
	else static if( is( T == short ) || is( T == ushort ) )
	{
		return	( val & 0x00FF ) << 8
			|	( val & 0xFF00 ) >> 8;
	}
	else static if( is( T == int ) || is( T == uint ) )
	{
		return	( val & 0x000000FF ) << 24
			|	( val & 0x0000FF00 ) << 8
			|	( val & 0x00FF0000 ) >> 8
			|	( val & 0xFF000000 ) >> 24;
	}
	else static if( is( T == long ) || is( T == ulong ) )
	{
		return	( val & 0x00000000000000FFL ) << 56
			|	( val & 0x000000000000FF00L ) << 40
			|	( val & 0x0000000000FF0000L ) << 24
			|	( val & 0x00000000FF000000L ) << 8
			|	( val & 0x000000FF00000000L ) >> 8
			| 	( val & 0x0000FF0000000000L ) >> 24
			| 	( val & 0x00FF000000000000L ) >> 40
			| 	( val & 0xFF00000000000000L ) >> 56;
	}
}

auto Fetch( T )( const( char )[] buffer )
{
	T val = cast( T )buffer[ 0 ];
	static if( T.sizeof >= 2 )
	{
		val |=	cast( T )buffer[ 1 ] << 8;
	}
	static if( T.sizeof >= 4 )
	{
		val |=	cast( T )buffer[ 2 ] << 16
			|	cast( T )buffer[ 3 ] << 24;
	}
	static if( T.sizeof == 8 )
	{
		val |=	cast( T )buffer[ 4 ] << 32
			|	cast( T )buffer[ 5 ] << 40
			|	cast( T )buffer[ 6 ] << 48
			|	cast( T )buffer[ 7 ] << 56;
	}

	return val;
}

