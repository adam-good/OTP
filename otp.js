/*
Function Details

    HMAC(K, m) = H( (k_ XOR opad) || H( (K_ XOR ipad) || m )  )
    Where:
        H       is a cryptographic hash function (I'll use sha1)
        K       is the secret key
        m       is the message (in our case a counter for HOTP implimentation)
        K_      is a variation of K where len(K) = B
                    if (K < B) then pad K with 0s
                    if (K > B) then hash K such that len(hash(K)) = B
        B       is the blocksize of H (512 bits [64 bytes] for sha1)
        opad    is the outer padding where len(opad) = B
        ipad    is the inner padding where len(ipad) = B

        ||      means concatination

    Info From https://en.wikipedia.org/wiki/Hash-based_message_authentication_code#Definition
*/
var hmac = function(key, message) {
    var blocksize = 64;

    // First ensure the key is a suitable length
    // the key must have B*2(128) hex characters to be B(64) bytes
    if (key.length < blocksize)
        K_ = key + String.fromCharCode(0).repeat(blocksize - key.length);
    else if (key.length > blocksize)
        K_ = key.slice(0, blocksize);
    else
        K_ = key;

    // Next generate opad and ipad
    var opad = String.fromCharCode(0x5C).repeat(blocksize);
    var ipad = String.fromCharCode(0x36).repeat(blocksize);

    // Perform our xor's
    var K_xor_opad = '';
    var K_xor_ipad = '';
    for (var i = 0; i < K_.length; ++i) {
        var k = K_.charCodeAt(i);
        var op = opad.charCodeAt(i);
        var ip = ipad.charCodeAt(i)
        K_xor_opad += String.fromCharCode(k ^ op);
        K_xor_ipad += String.fromCharCode(k ^ ip);
    }

    // Calculate the inner hash: H( (K_ XOR ipad) || m )
    // Note that it comes out as a string so we convert it to a byte array
    var innerStr = sha1(K_xor_ipad + message);
    var innerBytes = [];
    for (var i = 0; i < innerStr.length; i += 2) {
        var byteStr = innerStr[i] + innerStr[i+1];
        var byte = parseInt(byteStr, 16);
        innerBytes.push(byte);
    }

    var outerStr = sha1(innerBytes);
    outerBytes = []

    for (var i = 0; i < outerStr.length; i += 2) {
        var byteStr = outerStr[i] + outerStr[i+1];
        var byte = parseInt(byteStr, 16);
        outerBytes.push(byte);
    }

    return outerBytes;
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
var hotp = function(key, counter) {
    var h = this.hmac(key, counter);
    var codeLen = 6; // the length of out output code
    var code = '';

    // Get the passcode from the first however many bytes of the hash
    htop_value = h.slice(0,codeLen);
    for (var i = 0; i < codeLen; i++) {
        code += htop_value[i] % 10;
    }

    return code;
}

/*
    TOTP Definition:
        https://en.wikipedia.org/wiki/Time-based_One-time_Password_Algorithm

    This function is exactly like HOTP but uses the current time as the counter
    Usually we round the time to 30 seconds or so to ensure the codes last long enough to be used
*/
// This literally just calls hotp but uses the current time (rounded to 30 seconds) as the message
var totp = function(key) {
    var TC = Math.floor(new Date().getTime() / 1000 / 30);
    return this.hotp(key, TC.toString());
}
