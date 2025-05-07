/*
 * Boost Software License - Version 1.0
 * https://www.boost.org/LICENSE_1_0.txt
*/
module aegis;

/// AEGIS C bindings
public import c.aegisc; // @system

/// AEGIS 128
public import aegis.aegis128;

/// AEGIS 256
public import aegis.aegis256;

/// Verify MAC for AEGIS-128L (N=16) or AEGIS-256 (N=32)
auto aegis_verify(int N)(const(ubyte)[] x, const(ubyte)[] y) @trusted @nogc
        if (N == aegis128l_KEYBYTES || N == aegis256_KEYBYTES)
{
    static if (N == aegis128l_KEYBYTES)
        return aegis_verify_16(x.ptr, y.ptr);
    else
        return aegis_verify_32(x.ptr, y.ptr);
}
