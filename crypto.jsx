import "js.jsx";

class Crypto {
  static var _BASE64CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

  static function sha256(data : string) : number[] {
    return new Sha256().update(data).finalize();
  }

  static function toHex(bits : number[]) : string {
    var out = '';
    for (var i = 0, n = bits.length; i < n; ++i)
      out += ((bits[i] | 0) + 0xF00000000000).toString(16).substring(4);
    return out.substring(0, Crypto._bitLength(bits) / 4);    
  }

  static function toBase64(arr : number[]) : string {
    return Crypto.toBase64(arr, false);
  }

  static function toBase64(arr : number[], urlSafe : boolean) : string {
    var out = "";
    var c = Crypto._BASE64CHARS;
    var bits = 0;
    var ta = 0;
    var bl = Crypto._bitLength(arr);

    if (urlSafe)
      c = c.substring(0, 62) + '-_';

    var i = 0;
    while (out.length * 6 < bl) {
      var v = i == arr.length ? 0 : arr[i] as number;
      out += c.charAt((ta ^ v >>> bits) >>> 26);
      if (bits < 6) {
        ta = v << (6 - bits);
        bits += 26;
        i++;
      } else {
        ta <<= 6;
        bits -= 6;
      }
    }

    while ((out.length & 3) != 0)
      out += '=';
    return out;
  }

  static function fromUtf8(str : string) : number[] {
    str = Crypto._escapeString(str);
    var out = [] : number[];
    var tmp = 0;
    var i : number;

    for (i = 0; i < str.length; i++) {
      tmp = tmp << 8 | str.charCodeAt(i);
      if ((i & 3) == 3) {
        out.push(tmp);
        tmp = 0;
      }
    }

    if ((i & 3) != 0)
      out.push(Crypto._partial(8 * (i & 3), tmp));

    return out;
  }

  static function _escapeString(str : string) : string {
    var unescape = js.global['unescape'] as function(:string) : string;
    var encodeURIComponent = js.global['encodeURIComponent'] as function(:string) : string;
    return unescape(encodeURIComponent(str));
  }


  // Bit array operations
  static function _bitSlice(a : number[], bstart : number) : number[] {
    return Crypto._shiftRight(
      a.slice(bstart/32),
      32 - (bstart & 31)).slice(1);
  }

  static function _bitSlice(a : number[], bstart : number, bend : number) : number[] {
    a = Crypto._shiftRight(
      a.slice(bstart/32),
      32 - (bstart & 31)).slice(1);
    return Crypto._clamp(a, bend - bstart);
  }

  // Extract a number packed into a bit array.
  static function _extract(a : number[], bstart : number, blength : number) : number {
    var x = 0;
    var sh = Math.floor((-bstart-blength) & 31);
    if ((bstart + blength - 1 ^ bstart) & -32) {
      // it crosses a boundary
      x = (a[bstart/32|0] << (32- sh)) ^ (a[bstart/32+1|0] >>> sh);
    } else {
      // within a single word
      x = a[bstart/32|0] >>> sh;
    }
    return x & ((1<<blength) - 1);
  }

  // Concats two bit arrays.
  static function _concat(a : number[], b : number[]) : number[] {
    if (a.length == 0 || b.length == 0)
      return a.concat(b);

    var last = a[a.length - 1];
    var shift = Crypto._getPartial(last);
    if (shift == 32) {
      return a.concat(b);
    } else {
      return Crypto._shiftRight(b, shift, last | 0, a.slice(0, a.length - 1));
    }
  }

  // Find the length of an array of bits.
  static function _bitLength(a : number[]) : number {
    var l = a.length;
    if (l == 0)
      return 0;

    var x = a[l - 1];
    return (l - 1) * 32 + Crypto._getPartial(x);
  }

  // Truncate an array.
  static function _clamp(a : number[], len : number) : number[] {
    if (a.length * 32 < len)
      return a;
    a = a.slice(0, Math.ceil(len / 32));
    var l = a.length;
    len = len & 31;
    if (l > 0 && len != 0)
      a[l - 1] = Crypto._partial(len, a[l - 1] & 0x80000000 >> (len - 1), 1);
    return a;
  }

  static function _partial(len : number, x : number) : number {
    return Crypto._partial(len, x, 0);
  }

  // Make a partial word for a bit array.
  static function _partial(len : number, x : number, end : number) : number {
    if (len == 32)
      return x;
    return (end == 1 ? x|0 : x << (32 - len)) + len * 0x10000000000;
  }

  static function _getPartial(x : number) : number {
    var y = Math.round(x/0x10000000000);
    return y != 0 ? y : 32;
  }

  static function _shiftRight(a : number[], shift : number) : number[] {
    return Crypto._shiftRight(a, shift, 0, [] : number[]);
  }
  static function _shiftRight(a : number[], shift : number, carry : number) : number[] {
    return Crypto._shiftRight(a, shift, carry, [] : number[]);
  }

  static function _shiftRight(a : number[], shift : number, carry : number, out : number[]) : number[] {
    for (;shift >= 32; shift -= 32) {
      out.push(carry);
      carry = 0;
    }

    if (shift == 0)
      return out.concat(a);

    for (var i = 0; i < a.length; i++) {
      out.push(carry | a[i] >>> shift);
      carry = a[i] << (32 - shift);
    }

    var last2 = a.length > 0 ? a[a.length - 1] as number : 0;
    var shift2 = Crypto._getPartial(last2);
    out.push(Crypto._partial(
      shift + shift2 & 31,
      (shift + shift2 > 32) ? carry : out.pop() as number,
      1));
    return out;
  }  

}

class Sha256 {
  static var _init =
    [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19] : number[];
  static var _key =
    [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
     0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
     0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
     0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
     0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
     0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
     0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
     0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2] : number[];

  var _h : number[];
  var _b : number[];
  var _n : number;

  function constructor() {
    this.reset();
  }

  function reset() : Sha256 {
    this._h = Sha256._init.slice(0);
    this._b = [] : number[];
    this._n = 0;
    return this;
  }

  function update(data : string) : Sha256 {
    return this.update(Crypto.fromUtf8(data));
  }

  function update(data : number[]) : Sha256 {
    var i;
    var b = this._b = Crypto._concat(this._b, data);
    var on = this._n;
    var nn = this._n = on + Crypto._bitLength(data);
    for (i = 512 + on & -512; i <= nn; i += 512)
      this._block(b.splice(0, 16));
    return this;
  }

  function finalize() : number[] {
    var b = this._b;
    var h = this._h;

    // Round out and push the buffer
    b = Crypto._concat(b, [Crypto._partial(1, 1)]);

    // Round out the buffer to a multiple of 16 words
    for (var i = b.length + 2; (i & 15) != 0; i++)
      b.push(0);

    // append the length
    b.push(Math.floor(this._n / 0x100000000));
    b.push(this._n | 0);

    while (b.length != 0)
      this._block(b.splice(0, 16));

    this.reset();
    return h;
  }

  function _block(words : number[]) : void {
    var w = words.slice(0);
    var h = this._h;
    var k = Sha256._key;
    var h0 = h[0];
    var h1 = h[1];
    var h2 = h[2];
    var h3 = h[3];
    var h4 = h[4];
    var h5 = h[5];
    var h6 = h[6];
    var h7 = h[7];

    var tmp = 0, a = 0, b = 0;
    for (var i = 0; i < 64; ++i) {
      if (i<16) {
        tmp = w[i];
      } else {
        a   = w[(i+1 ) & 15];
        b   = w[(i+14) & 15];
        tmp = w[i&15] = ((a>>>7  ^ a>>>18 ^ a>>>3  ^ a<<25 ^ a<<14) + 
                         (b>>>17 ^ b>>>19 ^ b>>>10 ^ b<<15 ^ b<<13) +
                         w[i&15] + w[(i+9) & 15]) | 0;
      }
      
      tmp = (tmp + h7 + (h4>>>6 ^ h4>>>11 ^ h4>>>25 ^ h4<<26 ^ h4<<21 ^ h4<<7) +  (h6 ^ h4&(h5^h6)) + k[i]); // | 0;
      
      // shift register
      h7 = h6; h6 = h5; h5 = h4;
      h4 = h3 + tmp | 0;
      h3 = h2; h2 = h1; h1 = h0;

      h0 = (tmp +  ((h1&h2) ^ (h3&(h1^h2))) + (h1>>>2 ^ h1>>>13 ^ h1>>>22 ^ h1<<30 ^ h1<<19 ^ h1<<10)) | 0;
    }

    h[0] = h[0] + h0 | 0;
    h[1] = h[1] + h1 | 0;
    h[2] = h[2] + h2 | 0;
    h[3] = h[3] + h3 | 0;
    h[4] = h[4] + h4 | 0;
    h[5] = h[5] + h5 | 0;
    h[6] = h[6] + h6 | 0;
    h[7] = h[7] + h7 | 0;
  }
}