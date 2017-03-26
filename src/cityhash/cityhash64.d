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
// This module contains the 64-bit implementation of CityHash. This code is
// fully CTFE compliant.

module cityhash.cityhash64;

import cityhash.cityhash;

// Hash function for a byte array.
ulong CityHash64( const( char )[] buffer );

// Hash function for a byte array.  For convenience, a 64-bit seed is also
// hashed into the result.
ulong CityHash64WithSeed( const( char )[] buffer, ulong seed );

// Hash function for a byte array.  For convenience, two seeds are also
// hashed into the result.
ulong CityHash64WithSeeds( const( char )[] buffer, ulong seed0, ulong seed1 );

// Implementation follows
ulong CityHash64(const( char )[] buffer )
{
	if( buffer.length <= 32)
	{
		if( buffer.length <= 16 )
		{
			return HashLen0to16( buffer );
		}
		else
		{
			return HashLen17to32( buffer );
		}
	}
	else if( buffer.length <= 64 )
	{
		return HashLen33to64( buffer );
	}

	// For strings over 64 bytes we hash the end first, and then as we
	// loop we keep 56 bytes of state: v, w, x, y, and z.
	ulong x = Fetch!ulong( buffer[ buffer.length - 40 .. $ ] );
	ulong y = Fetch!ulong( buffer[ buffer.length - 16 .. $ ] ) + Fetch!ulong( buffer[ buffer.length - 56 .. $ ] );
	ulong z = HashLen16( Fetch!ulong( buffer[ buffer.length - 48 .. $ ] ) + buffer.length, Fetch!ulong( buffer[ buffer.length - 24 .. $ ] ) );

	Pair!( ulong, ulong ) v = WeakHashLen32WithSeeds( buffer[ buffer.length - 64 .. $ ], buffer.length, z );
	Pair!( ulong, ulong ) w = WeakHashLen32WithSeeds( buffer[ buffer.length - 32 .. $ ], y + k1, x );
	x = x * k1 + Fetch!ulong( buffer );

	// Decrease len to the nearest multiple of 64, and operate on 64-byte chunks.
	enum typeof( buffer.length ) AlignVal = cast( typeof( buffer.length ) )~63;
	buffer = buffer[ 0 .. ( buffer.length - 1 ) & AlignVal ];
	do
	{
		x = Rotate( x + y + v.first + Fetch!ulong( buffer[ 8 .. $ ] ), 37 ) * k1;
		y = Rotate( y + v.second + Fetch!ulong( buffer[ 48 .. $ ] ), 42 ) * k1;
		x ^= w.second;
		y += v.first + Fetch!ulong( buffer[ 40 .. $ ] );
		z = Rotate( z + w.first, 33 ) * k1;
		v = WeakHashLen32WithSeeds( buffer, v.second * k1, x + w.first );
		w = WeakHashLen32WithSeeds( buffer[ 32 .. $ ], z + w.second, y + Fetch!ulong( buffer[ 16 .. $ ] ) );
		Swap( z, x );
		buffer = buffer[ 64 .. $ ];
	} while ( buffer.length > 0 );

	return HashLen16( HashLen16( v.first, w.first ) + ShiftMix( y ) * k1 + z, HashLen16( v.second, w.second ) + x );
}

ulong CityHash64WithSeed( const( char )[] buffer, ulong seed )
{
	return CityHash64WithSeeds( buffer, k2, seed );
}

ulong CityHash64WithSeeds( const( char )[] buffer, ulong seed0, ulong seed1)
{
	return HashLen16( CityHash64( buffer ) - seed0, seed1 );
}

private:

ulong ShiftMix( ulong val )
{
  return val ^ ( val >> 47 );
}

ulong HashLen16( ulong u, ulong v )
{
	return Hash128to64( Pair!( ulong, ulong )(u, v) );
}

ulong HashLen16( ulong u, ulong v, ulong mul )
{
	// Murmur-inspired hashing.
	ulong a = ( u ^ v ) * mul;
	a ^= ( a >> 47 );
	ulong b = ( v ^ a ) * mul;
	b ^= ( b >> 47 );
	b *= mul;
	return b;
}

ulong HashLen0to16( const( char )[] buffer )
{
	if ( buffer.length >= 8 )
	{
		ulong mul = k2 + buffer.length * 2;
		ulong a = Fetch!ulong( buffer ) + k2;
		ulong b = Fetch!ulong( buffer[ buffer.length - 8 .. $ ] );
		ulong c = Rotate( b, 37 ) * mul + a;
		ulong d = ( Rotate (a, 25 ) + b ) * mul;
		return HashLen16( c, d, mul );
	}
	if ( buffer.length >= 4 )
	{
		ulong mul = k2 + buffer.length * 2;
		ulong a = Fetch!uint( buffer );
		return HashLen16( buffer.length + ( a << 3 ), Fetch!uint( buffer[ buffer.length - 4 .. $ ] ), mul );
	}
	if ( buffer.length > 0 )
	{
		uint a = cast( uint )buffer[ 0];
		uint b = cast( uint )buffer[ buffer.length >> 1 ];
		uint c = cast( uint )buffer[ buffer.length - 1];
		uint y = a + ( b << 8 );
		uint z = cast( uint )buffer.length + ( c << 2 );
		return ShiftMix( cast( ulong )( y * k2 ^ z * k0 ) ) * k2;
	}
	return k2;
}

// This probably works well for 16-byte strings as well, but it may be overkill
// in that case.
ulong HashLen17to32( const( char )[] buffer )
{
	ulong mul = k2 + buffer.length * 2;
	ulong a = Fetch!ulong( buffer ) * k1;
	ulong b = Fetch!ulong( buffer[ 8 .. $ ] );
	ulong c = Fetch!ulong( buffer[ buffer.length - 8 .. $ ] ) * mul;
	ulong d = Fetch!ulong( buffer[ buffer.length - 16 .. $ ] ) * k2;
	return HashLen16( Rotate( a + b, 43 ) + Rotate( c, 30 ) + d, a + Rotate( b + k2, 18 ) + c, mul );
}

// Return a 16-byte hash for 48 bytes.  Quick and dirty.
// Callers do best to use "random-looking" values for a and b.
Pair!( ulong, ulong ) WeakHashLen32WithSeeds( ulong w, ulong x, ulong y, ulong z, ulong a, ulong b)
{
	a += w;
	b = Rotate( b + a + z, 21 );
	ulong c = a;
	a += x;
	a += y;
	b += Rotate( a, 44 );
	return Pair!( ulong, ulong )(a + z, b + c);
}

// Return a 16-byte hash for s[0] ... s[31], a, and b.  Quick and dirty.
Pair!( ulong, ulong ) WeakHashLen32WithSeeds( const( char )[] buffer, ulong a, ulong b)
{
	return WeakHashLen32WithSeeds(	Fetch!ulong( buffer ),
									Fetch!ulong( buffer[ 8 .. $ ] ),
									Fetch!ulong( buffer[ 16 .. $ ] ),
									Fetch!ulong( buffer[ 24 .. $ ] ),
									a,
									b );
}

// Return an 8-byte hash for 33 to 64 bytes.
ulong HashLen33to64( const( char )[] buffer )
{
	ulong mul = k2 + buffer.length * 2;
	ulong a = Fetch!ulong( buffer ) * k2;
	ulong b = Fetch!ulong( buffer[ 8 .. $ ] );
	ulong c = Fetch!ulong( buffer[ buffer.length - 24 .. $ ] );
	ulong d = Fetch!ulong( buffer[ buffer.length - 32 .. $ ] );
	ulong e = Fetch!ulong( buffer[ 16 .. $ ] ) * k2;
	ulong f = Fetch!ulong( buffer[ 24 .. $ ] ) * 9;
	ulong g = Fetch!ulong( buffer[ buffer.length - 8 .. $ ] );
	ulong h = Fetch!ulong( buffer[ buffer.length - 16 .. $ ] ) * mul;
	ulong u = Rotate( a + g, 43 ) + ( Rotate( b, 30 ) + c ) * 9;
	ulong v = ( ( a + g ) ^ d ) + f + 1;
	ulong w = ByteSwap( ( u + v ) * mul ) + h;
	ulong x = Rotate(e + f, 42) + c;
	ulong y = ( ByteSwap( (v + w) * mul ) + g ) * mul;
	ulong z = e + f + c;
	a = ByteSwap( ( x + z ) * mul + y ) + b;
	b = ShiftMix( ( z + a ) * mul + d + h ) * mul;
	return b + x;
}

// Hash 128 input bits down to 64 bits of output.
// This is intended to be a reasonably good hash function.
ulong Hash128to64( const( Pair!( ulong, ulong ) ) x )
{
	// Murmur-inspired hashing.
	enum ulong kMul = 0x9ddfea08eb382d69L;
	ulong a = ( x.first ^ x.second ) * kMul;
	a ^= ( a >> 47 );
	ulong b = ( x.second ^ a ) * kMul;
	b ^= ( b >> 47 );
	b *= kMul;
	return b;
}
