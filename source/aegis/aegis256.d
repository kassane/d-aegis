/*
 * Boost Software License - Version 1.0
 * https://www.boost.org/LICENSE_1_0.txt
*/
module aegis.aegis256;

/// AEGIS C bindings
import c.aegisc; // @system
import core.stdc.string : memset;

/**
 * AEGIS-256 encryption/decryption state.
 *
 * Manages the lifecycle of an `aegis256_state` object, ensuring proper initialization
 * and cleanup in a `@nogc` and `@trusted` context.
 *
 * Examples:
 * ---
 * ubyte[32] key = [0x01, 0x02, ..., 0x20];
 * ubyte[32] nonce = [0x00, 0x01, ..., 0x1F];
 * ubyte[] ad = [0x41, 0x42, 0x43]; // "ABC"
 * ubyte[] message = [0x48, 0x65, 0x6C, 0x6C, 0x6F]; // "Hello"
 * ubyte[128] ciphertext;
 * ubyte[16] mac;
 * size_t written;
 *
 * auto state = Aegis256State(key, nonce, ad);
 * state.encryptUpdate(ciphertext[], &written, message);
 * state.encryptDetachedFinal(ciphertext[written .. $], &written, mac[], 16);
 * ---
 */
struct Aegis256State
{
    private aegis256_state state; // Underlying C state
    private bool initialized; // Tracks initialization status

    /**
     * Initializes the AEGIS-256 state with the provided key, nonce, and associated data.
     *
     * Params:
     *   key = The encryption key (must be `aegis256_KEYBYTES` long).
     *   nonce = The nonce (must be `aegis256_NPUBBYTES` long).
     *   ad = The associated data (optional, can be empty).
     *
     * Throws:
     *   AssertError if key or nonce lengths are invalid.
     */
    @nogc @trusted
    this(const(ubyte)[] key, const(ubyte)[] nonce, const(ubyte)[] ad = null)
    {
        assert(key.length == aegis256_KEYBYTES, "Key length must be aegis256_KEYBYTES");
        assert(nonce.length == aegis256_NPUBBYTES, "Nonce length must be aegis256_NPUBBYTES");

        memset(&state, 0, aegis256_state.sizeof);
        aegis256_state_init(&state, ad.ptr, ad.length, nonce.ptr, key.ptr);
        initialized = true;
    }

    /**
     * Destructor to clean up the state.
     */
    @nogc @trusted ~this()
    {
        if (initialized)
        {
            memset(&state, 0, aegis256_state.sizeof);
            initialized = false;
        }
    }

    /**
     * Disabled copy constructor to prevent state duplication.
     */
    @disable this(this);

    /**
     * Encrypts a message chunk, producing ciphertext.
     *
     * Params:
     *   ciphertext = Buffer to store the ciphertext.
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
        return aegis256_state_encrypt_update(&state, ciphertext.ptr, ciphertext.length,
            written, message.ptr, message.length);
    }

    /**
     * Finalizes encryption in detached mode, producing the final ciphertext and MAC.
     *
     * Params:
     *   ciphertext = Buffer for remaining ciphertext.
     *   written = Pointer to store the number of bytes written.
     *   mac = Buffer for the MAC (must be `aegis256_ABYTES_MIN` to `aegis256_ABYTES_MAX`).
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
        assert(maclen >= aegis256_ABYTES_MIN && maclen <= aegis256_ABYTES_MAX, "Invalid MAC length");
        return aegis256_state_encrypt_detached_final(&state, ciphertext.ptr, ciphertext.length,
            written, mac.ptr, maclen);
    }

    /**
     * Decrypts a ciphertext chunk, producing plaintext.
     *
     * Params:
     *   plaintext = Buffer to store the plaintext.
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
        return aegis256_state_decrypt_detached_update(&state, plaintext.ptr, plaintext.length,
            written, ciphertext.ptr, ciphertext.length);
    }

    /**
     * Finalizes decryption in detached mode, verifying the MAC and producing final plaintext.
     *
     * Params:
     *   plaintext = Buffer for remaining plaintext.
     *   written = Pointer to store the number of bytes written.
     *   mac = The MAC to verify (must be `aegis256_ABYTES_MIN` to `aegis256_ABYTES_MAX`).
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
        assert(maclen >= aegis256_ABYTES_MIN && maclen <= aegis256_ABYTES_MAX, "Invalid MAC length");
        return aegis256_state_decrypt_detached_final(&state, plaintext.ptr, plaintext.length,
            written, mac.ptr, maclen);
    }
}

/**
 * AEGIS-256 MAC state.
 *
 * Manages the lifecycle of an `aegis256_mac_state` object in a `@nogc` and `@trusted` context.
 *
 * Examples:
 * ---
 * ubyte[32] key = [0x01, 0x02, ..., 0x20];
 * ubyte[32] nonce = [0x00, 0x01, ..., 0x1F];
 * ubyte[] message = [0x48, 0x65, 0x6C, 0x6C, 0x6F]; // "Hello"
 * ubyte[16] mac;
 *
 * auto macState = Aegis256MACState(key, nonce);
 * macState.update(message);
 * macState.finalize(mac[], 16);
 * ---
 */
struct Aegis256MACState
{
    private aegis256_mac_state state; // Underlying C MAC state
    private bool initialized; // Tracks initialization status

    /**
     * Initializes the AEGIS-256 MAC state with the provided key and nonce.
     *
     * Params:
     *   key = The key (must be `aegis256_KEYBYTES` long).
     *   nonce = The nonce (must be `aegis256_NPUBBYTES` long).
     *
     * Throws:
     *   AssertError if key or nonce lengths are invalid.
     */
    @nogc @trusted
    this(const(ubyte)[] key, const(ubyte)[] nonce)
    {
        assert(key.length == aegis256_KEYBYTES, "Key length must be aegis256_KEYBYTES");
        assert(nonce.length == aegis256_NPUBBYTES, "Nonce length must be aegis256_NPUBBYTES");

        memset(&state, 0, aegis256_mac_state.sizeof);
        aegis256_mac_init(&state, key.ptr, nonce.ptr);
        initialized = true;
    }

    /**
     * Destructor to clean up the MAC state.
     */
    @nogc @trusted ~this()
    {
        if (initialized)
        {
            aegis256_mac_reset(&state);
            memset(&state, 0, aegis256_mac_state.sizeof);
            initialized = false;
        }
    }

    /**
     * Disabled copy constructor to prevent state duplication.
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
        return aegis256_mac_update(&state, message.ptr, message.length);
    }

    /**
     * Finalizes the MAC computation, producing the MAC.
     *
     * Params:
     *   mac = Buffer to store the MAC (must be `aegis256_ABYTES_MIN` to `aegis256_ABYTES_MAX`).
     *   maclen = Length of the MAC.
     *
     * Returns:
     *   0 on success, or a negative error code on failure.
     */
    @nogc @trusted
    int finalize(ubyte[] mac, size_t maclen)
    {
        assert(initialized, "MAC state not initialized");
        assert(maclen >= aegis256_ABYTES_MIN && maclen <= aegis256_ABYTES_MAX, "Invalid MAC length");
        return aegis256_mac_final(&state, mac.ptr, maclen);
    }

    /**
     * Verifies a MAC against the computed MAC.
     *
     * Params:
     *   mac = The MAC to verify (must be `aegis256_ABYTES_MIN` to `aegis256_ABYTES_MAX`).
     *   maclen = Length of the MAC.
     *
     * Returns:
     *   0 if valid, -1 if verification fails, or another negative error code on failure.
     */
    @nogc @trusted
    int verify(const(ubyte)[] mac, size_t maclen)
    {
        assert(initialized, "MAC state not initialized");
        assert(maclen >= aegis256_ABYTES_MIN && maclen <= aegis256_ABYTES_MAX, "Invalid MAC length");
        return aegis256_mac_verify(&state, mac.ptr, maclen);
    }

    /**
     * Resets the MAC state for reuse with the same key and nonce.
     */
    @nogc @trusted
    void reset()
    {
        assert(initialized, "MAC state not initialized");
        aegis256_mac_reset(&state);
    }
}

/**
 * AEGIS-256x2 encryption/decryption state.
 *
 * Manages the lifecycle of an `aegis256x2_state` object in a `@nogc` and `@trusted` context.
 */
struct Aegis256x2State
{
    private aegis256x2_state state; // Underlying C state
    private bool initialized; // Tracks initialization status

    /**
     * Initializes the AEGIS-256x2 state with the provided key, nonce, and associated data.
     *
     * Params:
     *   key = The encryption key (must be `aegis256x2_KEYBYTES` long).
     *   nonce = The nonce (must be `aegis256x2_NPUBBYTES` long).
     *   ad = The associated data (optional, can be empty).
     *
     * Throws:
     *   AssertError if key or nonce lengths are invalid.
     */
    @nogc @trusted
    this(const(ubyte)[] key, const(ubyte)[] nonce, const(ubyte)[] ad = null)
    {
        assert(key.length == aegis256x2_KEYBYTES, "Key length must be aegis256x2_KEYBYTES");
        assert(nonce.length == aegis256x2_NPUBBYTES, "Nonce length must be aegis256x2_NPUBBYTES");

        memset(&state, 0, aegis256x2_state.sizeof);
        aegis256x2_state_init(&state, ad.ptr, ad.length, nonce.ptr, key.ptr);
        initialized = true;
    }

    /**
     * Destructor to clean up the state.
     */
    @nogc @trusted ~this()
    {
        if (initialized)
        {
            memset(&state, 0, aegis256x2_state.sizeof);
            initialized = false;
        }
    }

    /**
     * Disabled copy constructor to prevent state duplication.
     */
    @disable this(this);

    /**
     * Encrypts a message chunk, producing ciphertext.
     *
     * Params:
     *   ciphertext = Buffer to store the ciphertext.
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
        return aegis256x2_state_encrypt_update(&state, ciphertext.ptr, ciphertext.length,
            written, message.ptr, message.length);
    }

    /**
     * Finalizes encryption in detached mode, producing the final ciphertext and MAC.
     *
     * Params:
     *   ciphertext = Buffer for remaining ciphertext.
     *   written = Pointer to store the number of bytes written.
     *   mac = Buffer for the MAC (must be `aegis256x2_ABYTES_MIN` to `aegis256x2_ABYTES_MAX`).
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
        assert(maclen >= aegis256x2_ABYTES_MIN && maclen <= aegis256x2_ABYTES_MAX, "Invalid MAC length");
        return aegis256x2_state_encrypt_detached_final(&state, ciphertext.ptr, ciphertext.length,
            written, mac.ptr, maclen);
    }

    /**
     * Decrypts a ciphertext chunk, producing plaintext.
     *
     * Params:
     *   plaintext = Buffer to store the plaintext.
     *   written = Pointer to store the number of bytes written.
     *   ciphertext = The ciphertext to decrypt.
     *
     * Returns:
     *   0 on success, or a negative error code on failure.
     */
    @nogc @trusted
    int decryptDetachedUpdate(ubyte[] plaintext, size_t* written, const(ubyte)[] associated_data)
    {
        assert(initialized, "State not initialized");
        assert(written !is null, "Written pointer cannot be null");
        return aegis256x2_state_decrypt_detached_update(&state, plaintext.ptr, plaintext.length,
            written, associated_data.ptr, associated_data.length);
    }

    /**
     * Finalizes decryption in detached mode, verifying the MAC and producing final plaintext.
     *
     * Params:
     *   plaintext = Buffer for remaining plaintext.
     *   written = Pointer to store the number of bytes written.
     *   mac = The MAC to verify (must be `aegis256x2_ABYTES_MIN` to `aegis256x2_ABYTES_MAX`).
     *   maclen = Length of the MAC.
     *
     * Returns:
     *laws
     *   0 on success, -1 if MAC verification fails, or another negative error code on failure.
     */
    @nogc @trusted
    int decryptDetachedFinal(ubyte[] plaintext, size_t* written, const(ubyte)[] mac, size_t maclen)
    {
        assert(initialized, "State not initialized");
        assert(written !is null, "Written pointer cannot be null");
        assert(maclen >= aegis256x2_ABYTES_MIN && maclen <= aegis256x2_ABYTES_MAX, "Invalid MAC length");
        return aegis256x2_state_decrypt_detached_final(&state, plaintext.ptr, plaintext.length,
            written, mac.ptr, maclen);
    }
}

/**
 * AEGIS-256x2 MAC state.
 *
 * Manages the lifecycle of an `aegis256x2_mac_state` object in a `@nogc` and `@trusted` context.
 */
struct Aegis256x2MACState
{
    private aegis256x2_mac_state state; // Underlying C MAC state
    private bool initialized; // Tracks initialization status

    /**
     * Initializes the AEGIS-256x2 MAC state with the provided key and nonce.
     *
     * Params:
     *   key = The key (must be `aegis256x2_KEYBYTES` long).
     *   nonce = The nonce (must be `aegis256x2_NPUBBYTES` long).
     *
     * Throws:
     *   AssertError if key or nonce lengths are invalid.
     */
    @nogc @trusted
    this(const(ubyte)[] key, const(ubyte)[] nonce)
    {
        assert(key.length == aegis256x2_KEYBYTES, "Key length must be aegis256x2_KEYBYTES");
        assert(nonce.length == aegis256x2_NPUBBYTES, "Nonce length must be aegis256x2_NPUBBYTES");

        memset(&state, 0, aegis256x2_mac_state.sizeof);
        aegis256x2_mac_init(&state, key.ptr, nonce.ptr);
        initialized = true;
    }

    /**
     * Destructor to clean up the MAC state.
     */
    @nogc @trusted ~this()
    {
        if (initialized)
        {
            aegis256x2_mac_reset(&state);
            memset(&state, 0, aegis256x2_mac_state.sizeof);
            initialized = false;
        }
    }

    /**
     * Disabled copy constructor to prevent state duplication.
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
        return aegis256x2_mac_update(&state, message.ptr, message.length);
    }

    /**
     * Finalizes the MAC computation, producing the MAC.
     *
     * Params:
     *   mac = Buffer to store the MAC (must be `aegis256x2_ABYTES_MIN` to `aegis256x2_ABYTES_MAX`).
     *   maclen = Length of the MAC.
     *
     * Returns:
     *   0 on success, or a negative error code on failure.
     */
    @nogc @trusted
    int finalize(ubyte[] mac, size_t maclen)
    {
        assert(initialized, "MAC state not initialized");
        assert(maclen >= aegis256x2_ABYTES_MIN && maclen <= aegis256x2_ABYTES_MAX, "Invalid MAC length");
        return aegis256x2_mac_final(&state, mac.ptr, maclen);
    }

    /**
     * Verifies a MAC against the computed MAC.
     *
     * Params:
     *   mac = The MAC to verify (must be `aegis256x2_ABYTES_MIN` to `aegis256x2_ABYTES_MAX`).
     *   maclen = Length of the MAC.
     *
     * Returns:
     *   0 if valid, -1 if verification fails, or another negative error code on failure.
     */
    @nogc @trusted
    int verify(const(ubyte)[] mac, size_t maclen)
    {
        assert(initialized, "MAC state not initialized");
        assert(maclen >= aegis256x2_ABYTES_MIN && maclen <= aegis256x2_ABYTES_MAX, "Invalid MAC length");
        return aegis256x2_mac_verify(&state, mac.ptr, maclen);
    }

    /**
     * Resets the MAC state for reuse with the same key and nonce.
     */
    @nogc @trusted
    void reset()
    {
        assert(initialized, "MAC state not initialized");
        aegis256x2_mac_reset(&state);
    }
}

/**
 * AEGIS-256x4 encryption/decryption state.
 *
 * Manages the lifecycle of an `aegis256x4_state` object in a `@nogc` and `@trusted` context.
 */
struct Aegis256x4State
{
    private aegis256x4_state state; // Underlying C state
    private bool initialized; // Tracks initialization status

    /**
     * Initializes the AEGIS-256x4 state with the provided key, nonce, and associated data.
     *
     * Params:
     *   key = The encryption key (must be `aegis256x4_KEYBYTES` long).
     *   nonce = The nonce (must be `aegis256x4_NPUBBYTES` long).
     *   ad = The associated data (optional, can be empty).
     *
     * Throws:
     *   AssertError if key or nonce lengths are invalid.
     */
    @nogc @trusted
    this(const(ubyte)[] key, const(ubyte)[] nonce, const(ubyte)[] ad = null)
    {
        assert(key.length == aegis256x4_KEYBYTES, "Key length must be aegis256x4_KEYBYTES");
        assert(nonce.length == aegis256x4_NPUBBYTES, "Nonce length must be aegis256x4_NPUBBYTES");

        memset(&state, 0, aegis256x4_state.sizeof);
        aegis256x4_state_init(&state, ad.ptr, ad.length, nonce.ptr, key.ptr);
        initialized = true;
    }

    /**
     * Destructor to clean up the state.
     */
    @nogc @trusted ~this()
    {
        if (initialized)
        {
            memset(&state, 0, aegis256x4_state.sizeof);
            initialized = false;
        }
    }

    /**
     * Disabled copy constructor to prevent state duplication.
     */
    @disable this(this);

    /**
     * Encrypts a message chunk, producing ciphertext.
     *
     * Params:
     *   ciphertext = Buffer to store the ciphertext.
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
        return aegis256x4_state_encrypt_update(&state, ciphertext.ptr, ciphertext.length,
            written, message.ptr, message.length);
    }

    /**
     * Finalizes encryption in detached mode, producing the final ciphertext and MAC.
     *
     * Params:
     *   ciphertext = Buffer for remaining ciphertext.
     *   written = Pointer to store the number of bytes written.
     *   mac = Buffer for the MAC (must be `aegis256x4_ABYTES_MIN` to `aegis256x4_ABYTES_MAX`).
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
        assert(maclen >= aegis256x4_ABYTES_MIN && maclen <= aegis256x4_ABYTES_MAX, "Invalid MAC length");
        return aegis256x4_state_encrypt_detached_final(&state, ciphertext.ptr, ciphertext.length,
            written, mac.ptr, maclen);
    }

    /**
     * Decrypts a ciphertext chunk, producing plaintext.
     *
     * Params:
     *   plaintext = Buffer to store the plaintext.
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
        return aegis256x4_state_decrypt_detached_update(&state, plaintext.ptr, plaintext.length,
            written, ciphertext.ptr, ciphertext.length);
    }

    /**
     * Finalizes decryption in detached mode, verifying the MAC and producing final plaintext.
     *
     * Params:
     *   plaintext = Buffer for remaining plaintext.
     *   written = Pointer to store the number of bytes written.
     *   mac = The MAC to verify (must be `aegis256x4_ABYTES_MIN` to `aegis256x4_ABYTES_MAX`).
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
        assert(maclen >= aegis256x4_ABYTES_MIN && maclen <= aegis256x4_ABYTES_MAX, "Invalid MAC length");
        return aegis256x4_state_decrypt_detached_final(&state, plaintext.ptr, plaintext.length,
            written, mac.ptr, maclen);
    }
}

/**
 * AEGIS-256x4 MAC state.
 *
 * Manages the lifecycle of an `aegis256x4_mac_state` object in a `@nogc` and `@trusted` context.
 */
struct Aegis256x4MACState
{
    private aegis256x4_mac_state state; // Underlying C MAC state
    private bool initialized; // Tracks initialization status

    /**
     * Initializes the AEGIS-256x4 MAC state with the provided key and nonce.
     *
     * Params:
     *   key = The key (must be `aegis256x4_KEYBYTES` long).
     *   nonce = The nonce (must be `aegis256x4_NPUBBYTES` long).
     *
     * Throws:
     *   AssertError if key or nonce lengths are invalid.
     */
    @nogc @trusted
    this(const(ubyte)[] key, const(ubyte)[] nonce)
    {
        assert(key.length == aegis256x4_KEYBYTES, "Key length must be aegis256x4_KEYBYTES");
        assert(nonce.length == aegis256x4_NPUBBYTES, "Nonce length must be aegis256x4_NPUBBYTES");

        memset(&state, 0, aegis256x4_mac_state.sizeof);
        aegis256x4_mac_init(&state, key.ptr, nonce.ptr);
        initialized = true;
    }

    /**
     * Destructor to clean up the MAC state.
     */
    @nogc @trusted ~this()
    {
        if (initialized)
        {
            aegis256x4_mac_reset(&state);
            memset(&state, 0, aegis256x4_mac_state.sizeof);
            initialized = false;
        }
    }

    /**
     * Disabled copy constructor to prevent state duplication.
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
        return aegis256x4_mac_update(&state, message.ptr, message.length);
    }

    /**
     * Finalizes the MAC computation, producing the MAC.
     *
     * Params:
     *   mac = Buffer to store the MAC (must be `aegis256x4_ABYTES_MIN` to `aegis256x4_ABYTES_MAX`).
     *   maclen = Length of the MAC.
     *
     * Returns:
     *   0 on success, or a negative error code on failure.
     */
    @nogc @trusted
    int finalize(ubyte[] mac, size_t maclen)
    {
        assert(initialized, "MAC state not initialized");
        assert(maclen >= aegis256x4_ABYTES_MIN && maclen <= aegis256x4_ABYTES_MAX, "Invalid MAC length");
        return aegis256x4_mac_final(&state, mac.ptr, maclen);
    }

    /**
     * Verifies a MAC against the computed MAC.
     *
     * Params:
     *   mac = The MAC to verify (must be `aegis256x4_ABYTES_MIN` to `aegis256x4_ABYTES_MAX`).
     *   maclen = Length of the MAC.
     *
     * Returns:
     *   0 if valid, -1 if verification fails, or another negative error code on failure.
     */
    @nogc @trusted
    int verify(const(ubyte)[] mac, size_t maclen)
    {
        assert(initialized, "MAC state not initialized");
        assert(maclen >= aegis256x4_ABYTES_MIN && maclen <= aegis256x4_ABYTES_MAX, "Invalid MAC length");
        return aegis256x4_mac_verify(&state, mac.ptr, maclen);
    }

    /**
     * Resets the MAC state for reuse with the same key and nonce.
     */
    @nogc @trusted
    void reset()
    {
        assert(initialized, "MAC state not initialized");
        aegis256x4_mac_reset(&state);
    }
}

version (unittest)
{
    @trusted
    @("AEGIS256")
    unittest
    {
        import std.random : uniform;
        import core.stdc.string : memcmp;

        // Initialize AEGIS library
        assert(aegis_init() == 0, "AEGIS initialization failed");

        // Common test data
        enum size_t bufferSize = 256; // Sufficient for test message and tail bytes
        ubyte[aegis256_KEYBYTES] key;
        foreach (ref k; key)
            k = cast(ubyte) uniform(0, bufferSize);
        ubyte[aegis256_NPUBBYTES] nonce;
        foreach (ref n; nonce)
            n = cast(ubyte) uniform(0, bufferSize);
        ubyte[] ad = cast(ubyte[]) "ABC";
        ubyte[] message = cast(ubyte[]) "Hello";
        ubyte[bufferSize] ciphertext;
        ubyte[aegis256_ABYTES_MIN] macMin;
        ubyte[aegis256_ABYTES_MAX] macMax;
        size_t written;

        // Test Aegis256State (encryption/decryption)
        {
            // Encryption
            auto encState = Aegis256State(key, nonce, ad);
            written = 0;
            assert(encState.encryptUpdate(ciphertext[], &written, message) == 0,
                "Aegis256State: Encryption update failed");
            assert(written <= ciphertext.length, "Aegis256State: Written bytes exceed buffer");
            size_t totalWritten = written;

            assert(encState.encryptDetachedFinal(ciphertext[totalWritten .. $], &written,
                    macMin[], aegis256_ABYTES_MIN) == 0, "Aegis256State: Encryption finalization failed");
            totalWritten += written;
            assert(totalWritten <= ciphertext.length, "Aegis256State: Total written bytes exceed buffer");

            // Decryption
            ubyte[bufferSize] decrypted;
            size_t decWritten;
            auto decState = Aegis256State(key, nonce, ad);
            decWritten = 0;
            assert(decState.decryptDetachedUpdate(decrypted[], &decWritten, ciphertext[0 .. totalWritten]) == 0,
                "Aegis256State: Decryption update failed");
            assert(decWritten <= decrypted.length, "Aegis256State: Decrypted bytes exceed buffer");
            size_t totalDecWritten = decWritten;

            assert(decState.decryptDetachedFinal(decrypted[totalDecWritten .. $], &decWritten,
                    macMin[], aegis256_ABYTES_MIN) == 0, "Aegis256State: Decryption finalization failed");
            totalDecWritten += decWritten;
            assert(totalDecWritten <= decrypted.length, "Aegis256State: Total decrypted bytes exceed buffer");
            assert(totalDecWritten >= message.length, "Aegis256State: Decrypted length too short");
            assert(decrypted[0 .. message.length] == message, "Aegis256State: Decrypted message mismatch");
        }

        // Test Aegis256MACState
        {
            auto macState = Aegis256MACState(key, nonce);
            assert(macState.update(message) == 0, "Aegis256MACState: MAC update failed");
            assert(macState.finalize(macMin[], aegis256_ABYTES_MIN) == 0,
                "Aegis256MACState: MAC finalization (min) failed");
            assert(macState.finalize(macMax[], aegis256_ABYTES_MAX) == 0,
                "Aegis256MACState: MAC finalization (max) failed");

            // Verify MAC (streaming)
            macState.reset();
            assert(macState.update(message) == 0, "Aegis256MACState: MAC update for verification failed");
            assert(macState.verify(macMin[], aegis256_ABYTES_MIN) == 0,
                "Aegis256MACState: MAC verification (min) failed");

            // Test reset
            macState.reset();
            assert(macState.update(message) == 0, "Aegis256MACState: MAC update after reset failed");
            ubyte[aegis256_ABYTES_MIN] newMac;
            assert(macState.finalize(newMac[], aegis256_ABYTES_MIN) == 0,
                "Aegis256MACState: MAC finalization after reset failed");
            assert(memcmp(macMin.ptr, newMac.ptr, aegis256_ABYTES_MIN) == 0,
                "Aegis256MACState: MACs do not match after reset");

            // Test invalid MAC
            macState.reset();
            assert(macState.update(message) == 0, "Aegis256MACState: MAC update for invalid verification failed");
            ubyte[aegis256_ABYTES_MIN] wrongMac = macMin;
            wrongMac[0] ^= 0xFF;
            assert(macState.verify(wrongMac[], aegis256_ABYTES_MIN) == -1,
                "Aegis256MACState: Invalid MAC verification did not fail");
        }
    }
}
