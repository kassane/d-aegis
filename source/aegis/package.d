/*
 * Boost Software License - Version 1.0
 * https://www.boost.org/LICENSE_1_0.txt
*/
module aegis;

/// AEGIS C bindings
public import c.aegisc; // @system
import core.stdc.string : memset;

/**
 * AEGIS-128L encryption/decryption state.
 *
 * This struct manages the lifecycle of an `aegis128l_state` object, ensuring proper
 * initialization and cleanup. It is designed to be used in a `@nogc` and `@trusted`
 * context, preventing memory leaks and ensuring safe usage of the underlying C API.
 *
 * Examples:
 * ---
 * ubyte[16] key = [0x01, 0x02, ..., 0x10];
 * ubyte[16] nonce = [0x00, 0x01, ..., 0x0F];
 * ubyte[] ad = [0x41, 0x42, 0x43]; // Associated data
 * ubyte[] message = [0x48, 0x65, 0x6C, 0x6C, 0x6F]; // "Hello"
 * ubyte[128] ciphertext;
 * ubyte[16] mac;
 * size_t written;
 *
 * auto state = Aegis128LState(key, nonce, ad);
 * state.encryptUpdate(ciphertext[], &written, message);
 * state.encryptDetachedFinal(ciphertext[written .. $], &written, mac[], 16);
 * ---
 */
struct Aegis128LState
{
    private aegis128l_state state; // Underlying C state
    private bool initialized; // Tracks initialization status

    /**
     * Initializes the AEGIS-128L state with the provided key, nonce, and associated data.
     *
     * Params:
     *   key = The encryption key (must be `aegis128l_KEYBYTES` long).
     *   nonce = The nonce (must be `aegis128l_NPUBBYTES` long).
     *   ad = The associated data (optional, can be empty).
     *
     * Throws:
     *   AssertError if key or nonce lengths are invalid.
     */
    @nogc @trusted
    this(const(ubyte)[] key, const(ubyte)[] nonce, const(ubyte)[] ad = null)
    {
        assert(key.length == aegis128l_KEYBYTES, "Key length must be aegis128l_KEYBYTES");
        assert(nonce.length == aegis128l_NPUBBYTES, "Nonce length must be aegis128l_NPUBBYTES");

        // Zero-initialize the state to ensure clean slate
        memset(&state, 0, aegis128l_state.sizeof);
        aegis128l_state_init(&state, ad.ptr, ad.length, nonce.ptr, key.ptr);
        initialized = true;
    }

    /**
     * Destructor to clean up the state.
     *
     * Ensures the state is securely zeroed out when the struct goes out of scope.
     */
    @nogc @trusted ~this()
    {
        if (initialized)
        {
            memset(&state, 0, aegis128l_state.sizeof);
            initialized = false;
        }
    }

    /**
     * Disabled copy constructor to prevent accidental state duplication.
     */
    @disable this(this);

    /**
     * Encrypts a message chunk, producing ciphertext.
     *
     * Params:
     *   ciphertext = Buffer to store the ciphertext (must be large enough).
     *   written = Pointer to store the number of bytes written.
     *   message = The plaintext message to encrypt.
     *
     * Returns:
     *   0 on success, or a negative error code on failure.
     */
    @nogc @trusted
    int encryptUpdate(ubyte[] ciphertext, size_t* written, const(ubyte)[] message)
    {
        assert(initialized, "State not initialized");
        assert(written !is null, "Written pointer cannot be null");
        return aegis128l_state_encrypt_update(&state, ciphertext.ptr, ciphertext.length,
            written, message.ptr, message.length);
    }

    /**
     * Finalizes encryption in detached mode, producing the final ciphertext and MAC.
     *
     * Params:
     *   ciphertext = Buffer for remaining ciphertext (must be large enough).
     *   written = Pointer to store the number of bytes written.
     *   mac = Buffer for the MAC (must be between `aegis128l_ABYTES_MIN` and `aegis128l_ABYTES_MAX`).
     *   maclen = Length of the MAC.
     *
     * Returns:
     *   0 on success, or a negative error code on failure.
     */
    @nogc @trusted
    int encryptDetachedFinal(ubyte[] ciphertext, size_t* written, ubyte[] mac, size_t maclen)
    {
        assert(initialized, "State not initialized");
        assert(written !is null, "Written pointer cannot be null");
        assert(maclen >= aegis128l_ABYTES_MIN && maclen <= aegis128l_ABYTES_MAX,
            "Invalid MAC length");
        return aegis128l_state_encrypt_detached_final(&state, ciphertext.ptr, ciphertext.length,
            written, mac.ptr, maclen);
    }

    /**
     * Decrypts a ciphertext chunk, producing plaintext.
     *
     * Params:
     *   plaintext = Buffer to store the plaintext (must be large enough).
     *   written = Pointer to store the number of bytes written.
     *   ciphertext = The ciphertext to decrypt.
     *
     * Returns:
     *   0 on success, or a negative error code on failure.
     */
    @nogc @trusted
    int decryptDetachedUpdate(ubyte[] plaintext, size_t* written, const(ubyte)[] ciphertext)
    {
        assert(initialized, "State not initialized");
        assert(written !is null, "Written pointer cannot be null");
        return aegis128l_state_decrypt_detached_update(&state, plaintext.ptr, plaintext.length,
            written, ciphertext.ptr, ciphertext.length);
    }

    /**
     * Finalizes decryption in detached mode, verifying the MAC and producing final plaintext.
     *
     * Params:
     *   plaintext = Buffer for remaining plaintext (must be large enough).
     *   written = Pointer to store the number of bytes written.
     *   mac = The MAC to verify (must be between `aegis128l_ABYTES_MIN` and `aegis128l_ABYTES_MAX`).
     *   maclen = Length of the MAC.
     *
     * Returns:
     *   0 on success, -1 if MAC verification fails, or another negative error code on failure.
     */
    @nogc @trusted
    int decryptDetachedFinal(ubyte[] plaintext, size_t* written, const(ubyte)[] mac, size_t maclen)
    {
        assert(initialized, "State not initialized");
        assert(written !is null, "Written pointer cannot be null");
        assert(maclen >= aegis128l_ABYTES_MIN && maclen <= aegis128l_ABYTES_MAX,
            "Invalid MAC length");
        return aegis128l_state_decrypt_detached_final(&state, plaintext.ptr, plaintext.length,
            written, mac.ptr, maclen);
    }
}

/**
 * RAII wrapper for the AEGIS-128L MAC state.
 *
 * This struct manages the lifecycle of an `aegis128l_mac_state` object, ensuring proper
 * initialization, updates, and cleanup. It is designed for `@nogc` and `@trusted` usage.
 *
 * Examples:
 * ---
 * ubyte[16] key = [0x01, 0x02, ..., 0x10];
 * ubyte[16] nonce = [0x00, 0x01, ..., 0x0F];
 * ubyte[] message = [0x48, 0x65, 0x6C, 0x6C, 0x6F]; // "Hello"
 * ubyte[16] mac;
 *
 * auto macState = Aegis128LMACState(key, nonce);
 * macState.update(message);
 * macState.finalize(mac[], 16);
 * ---
 */
struct Aegis128LMACState
{
    private aegis128l_mac_state state; // Underlying C MAC state
    private bool initialized; // Tracks initialization status

    /**
     * Initializes the AEGIS-128L MAC state with the provided key and nonce.
     *
     * Params:
     *   key = The key (must be `aegis128l_KEYBYTES` long).
     *   nonce = The nonce (must be `aegis128l_NPUBBYTES` long).
     *
     * Throws:
     *   AssertError if key or nonce lengths are invalid.
     */
    @nogc @trusted
    this(const(ubyte)[] key, const(ubyte)[] nonce)
    {
        assert(key.length == aegis128l_KEYBYTES, "Key length must be aegis128l_KEYBYTES");
        assert(nonce.length == aegis128l_NPUBBYTES, "Nonce length must be aegis128l_NPUBBYTES");

        // Zero-initialize the state
        memset(&state, 0, aegis128l_mac_state.sizeof);
        aegis128l_mac_init(&state, key.ptr, nonce.ptr);
        initialized = true;
    }

    /**
     * Destructor to clean up the MAC state.
     *
     * Ensures the state is securely zeroed out when the struct goes out of scope.
     */
    @nogc @trusted ~this()
    {
        if (initialized)
        {
            aegis128l_mac_reset(&state);
            memset(&state, 0, aegis128l_mac_state.sizeof);
            initialized = false;
        }
    }

    /**
     * Disabled copy constructor to prevent accidental state duplication.
     */
    @disable this(this);

    /**
     * Updates the MAC state with a message chunk.
     *
     * Params:
     *   message = The message to process.
     *
     * Returns:
     *   0 on success, or a negative error code on failure.
     */
    @nogc @trusted
    int update(const(ubyte)[] message)
    {
        assert(initialized, "MAC state not initialized");
        return aegis128l_mac_update(&state, message.ptr, message.length);
    }

    /**
     * Finalizes the MAC computation, producing the MAC.
     *
     * Params:
     *   mac = Buffer to store the MAC (must be between `aegis128l_ABYTES_MIN` and `aegis128l_ABYTES_MAX`).
     *   maclen = Length of the MAC.
     *
     * Returns:
     *   0 on success, or a negative error code on failure.
     */
    @nogc @trusted
    int finalize(ubyte[] mac, size_t maclen)
    {
        assert(initialized, "MAC state not initialized");
        assert(maclen >= aegis128l_ABYTES_MIN && maclen <= aegis128l_ABYTES_MAX,
            "Invalid MAC length");
        return aegis128l_mac_final(&state, mac.ptr, maclen);
    }

    /**
     * Verifies a MAC against the computed MAC.
     *
     * Params:
     *   mac = The MAC to verify (must be between `aegis128l_ABYTES_MIN` and `aegis128l_ABYTES_MAX`).
     *   maclen = Length of the MAC.
     *
     * Returns:
     *   0 if the MAC is valid, -1 if verification fails, or another negative error code on failure.
     */
    @nogc @trusted
    int verify(const(ubyte)[] mac, size_t maclen)
    {
        assert(initialized, "MAC state not initialized");
        assert(maclen >= aegis128l_ABYTES_MIN && maclen <= aegis128l_ABYTES_MAX,
            "Invalid MAC length");
        return aegis128l_mac_verify(&state, mac.ptr, maclen);
    }

    /**
     * Resets the MAC state for reuse with the same key and nonce.
     */
    @nogc @trusted
    void reset()
    {
        assert(initialized, "MAC state not initialized");
        aegis128l_mac_reset(&state);
    }
}

@trusted
unittest
{
    import core.stdc.string : memcmp;
    import std.random : uniform;

    // Initialize AEGIS library if required
    assert(aegis_init() == 0, "AEGIS initialization failed");

    // Test Aegis128LState encryption and decryption
    ubyte[aegis128l_KEYBYTES] key;
    foreach (ref k; key)
        k = cast(ubyte)(uniform(0, 256));
    ubyte[aegis128l_NPUBBYTES] nonce;
    foreach (ref n; nonce)
        n = cast(ubyte)(uniform(0, 256));

    ubyte[] ad = cast(ubyte[]) "ABC".ptr;
    ubyte[] message = cast(ubyte[]) "Hello".ptr;
    ubyte[128] ciphertext;
    ubyte[aegis128l_ABYTES_MIN] mac;
    size_t written;

    // Encryption
    {
        auto encState = Aegis128LState(key, nonce, ad);
        written = 0; // Explicitly initialize
        assert(encState.encryptUpdate(ciphertext[], &written, message) == 0,
            "Encryption update failed");
        assert(written <= ciphertext.length, "Written bytes exceed ciphertext buffer");
        size_t totalWritten = written;

        assert(encState.encryptDetachedFinal(ciphertext[totalWritten .. $], &written, mac[], 16) == 0,
            "Encryption finalization failed");
        totalWritten += written;
        assert(totalWritten <= ciphertext.length, "Total written bytes exceed ciphertext buffer");
    }

    // Decryption
    {
        ubyte[128] decrypted;
        size_t decWritten;
        auto decState = Aegis128LState(key, nonce, ad);
        decWritten = 0; // Explicitly initialize
        assert(decState.decryptDetachedUpdate(decrypted[], &decWritten, ciphertext[0 .. written]) == 0,
            "Decryption update failed");
        assert(decWritten <= decrypted.length, "Decrypted bytes exceed plaintext buffer");
        size_t totalDecWritten = decWritten;

        assert(decState.decryptDetachedFinal(decrypted[totalDecWritten .. $], &decWritten, mac[], 16) == 0,
            "Decryption finalization failed");
        totalDecWritten += decWritten;
        assert(totalDecWritten <= decrypted.length, "Total decrypted bytes exceed plaintext buffer");

        // Verify decrypted message matches original
        assert(totalDecWritten >= message.length, "Decrypted length too short");
        assert(decrypted[0 .. message.length] == message, "Decrypted message does not match original");
    }

    // Test Aegis128LMACState
    {
        auto macState = Aegis128LMACState(key, nonce);
        assert(macState.update(message) == 0, "MAC update failed");
        ubyte[16] computedMac;
        assert(macState.finalize(computedMac[], 16) == 0, "MAC finalization failed");
        // assert(macState.verify(computedMac[], 16) == 0, "MAC verification failed");

        // Test reset
        macState.reset();
        assert(macState.update(message) == 0, "MAC update after reset failed");
        ubyte[16] newMac;
        assert(macState.finalize(newMac[], 16) == 0, "MAC finalization after reset failed");
        assert(memcmp(computedMac.ptr, newMac.ptr, 16) == 0, "MACs do not match after reset");
    }

    // Test invalid MAC verification
    {
        auto macState = Aegis128LMACState(key, nonce);
        assert(macState.update(message) == 0, "MAC update failed");
        ubyte[16] wrongMac = mac;
        wrongMac[0] ^= 0xFF; // Corrupt MAC
        assert(macState.verify(wrongMac[], 16) == -1, "Invalid MAC verification did not fail");
    }
}
