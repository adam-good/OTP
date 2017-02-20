package otp

import (
    "fmt"
    "crypto/sha1"
    "time"
    "strconv"
)


/*
    HMAC Algorithm Definition:
        https://en.wikipedia.org/wiki/Hash-based_message_authentication_code

    HMAC(K,m) = H( (K' ⊕ opad) || H((K' ⊕ ipad) || m) )
where
    H is a cryptographic hash function,
    K is the secret key,
    m is the message to be authenticated,
    K' is another secret key, derived from the original key K (by padding K to the right with extra zeroes to the input block size of the hash function, or by hashing K if it is longer than that block size),
    || denotes concatenation,
    ⊕ denotes exclusive or (XOR),
    opad is the outer padding (0x5c5c5c…5c5c, one-block-long hexadecimal constant),
    ipad is the inner padding (0x363636…3636, one-block-long hexadecimal constant).
*/

func HMAC(key []byte, message []byte) []byte {
    var blocksize int = sha1.BlockSize

    /*
    *   First ensure that the len(key) = blocksize
    *       if len(key) < blocksize pad key with 0s
    *       if len(key) > blocksize hash key
    */
    if (len(key) < blocksize) {
        // initialize slice of 0s to pad the key
        var pad []byte = make([]byte, blocksize-len(key))
        key = append(key, pad...)
    } else if (len(key) > blocksize) {
        // TODO: hash key
        key = key[:blocksize]
    }

    /*
    *   opad (outer padding) = 0x5C5C5C...
    *   ipad is inner padding = 0x363636...
    *       len(opad) = blocksize
    *       len(ipad) = blocksize
    */
    var opad []byte
    var ipad []byte
    for len(opad) < blocksize {
        opad = append(opad, 0x5C)
        ipad = append(ipad, 0x36)
    }

    /*
    *   Calculate
    *       (K' ⊕ opad)
    *       (K' ⊕ ipad)
    */
    var key_xor_opad []byte = make([]byte, blocksize)
    var key_xor_ipad []byte = make([]byte, blocksize)
    for i := 0; i < blocksize; i++ {
        key_xor_opad[i] = key[i] ^ opad[i]
        key_xor_ipad[i] = key[i] ^ ipad[i]
    }

    /*
    *   Calculate:
    *       sum1 = H((K' ⊕ ipad) || m)
    *       sum2 = H( (K' ⊕ opad) || H((K' ⊕ ipad) || m) )
    */
    var sum1 [sha1.Size]byte = sha1.Sum(append(key_xor_ipad, message...))
    var sum2 [sha1.Size]byte = sha1.Sum(sum1[:])//sha1.Sum(append(key_xor_opad, sum1[:]...))

    return sum2[:]
}

/*
    HOTP Definition:
        https://en.wikipedia.org/wiki/HMAC-based_One-time_Password_Algorithm

K be a secret key
C be a counter
HMAC(K,C) = SHA1(K ⊕ 0x5c5c… ∥ SHA1(K ⊕ 0x3636… ∥ C)) with ⊕ as XOR, ∥ as concatenation, for more details see HMAC
Truncate be a function that selects 4 bytes from the result of the HMAC in a defined manner
Then HOTP(K,C) is mathematically defined by
HOTP(K,C) = Truncate(HMAC(K,C)) & 0x7FFFFFFF
The mask 0x7FFFFFFF sets the result's most significant bit to zero. This avoids problems if the result is interpreted as a signed number as some processors do.[1]
For HOTP to be useful for an individual to input to a system, the result must be converted into a HOTP value, a 6–8 digits number that is implementation dependent.
HOTP-Value = HOTP(K,C) mod 10d, where d is the desired number of digits
*/
func HOTP(key []byte, counter []byte) []byte {
    /*
    *   Define the code length and the slice to contain the code
    */
    var codeLen int = 6
    var code []byte

    /*
    *   Generate the hmac
    *       NOTE: Some implementations make sure the first byte is positive
    *               I don't think I need to do that in my implementation
    */
    var hmac []byte = HMAC(key, counter)

    /*
    *   Grab the first X bytes for the code
    *   mod the bytes to get our code
    *   TODO: Redo this...it's kinda hacky
    */
    code = hmac[0:codeLen]
    for i,b := range(code) {
        code[i] = b % 10
    }
    return code
}

/*
    TOTP Definition:
        https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm

    This function is exactly like HOTP but uses the current time as the counter
    Usually we round the time to 30 seconds or so to ensure the codes last long enough to be used
*/
func TOTP(key []byte) []byte {
    var t int64 = time.Now().Unix() / 30;
    var tstr string = strconv.FormatInt(t, 10)

    return HOTP(key, []byte(tstr));
}
