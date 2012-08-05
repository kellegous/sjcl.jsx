import "js.jsx";

class _BitArray {
  static function _escapeString(str : string) : string {
    var unescape = js.global['unescape'] as function(:string) : string;
    var encodeURIComponent = js.global['encodeURIComponent'] as function(:string) : string;
    return unescape(encodeURIComponent(str));
  }

  // Convert from a UTF-8 string to a bit array.
  static function _utf8ToBits(str : string) : number[] {
    str = _BitArray._escapeString(str);
    log str;
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
      out.push(_BitArray.partial(8 * (i & 3), tmp));

    return out;
  }

  static function bitSlice(a : number[], bstart : number) : number[] {
    return _BitArray._shiftRight(
      a.slice(bstart/32),
      32 - (bstart & 31)).slice(1);
  }

  static function bitSlice(a : number[], bstart : number, bend : number) : number[] {
    a = _BitArray._shiftRight(
      a.slice(bstart/32),
      32 - (bstart & 31)).slice(1);
    return _BitArray.clamp(a, bend - bstart);
  }

  // Extract a number packed into a bit array.
  static function extract(a : number[], bstart : number, blength : number) : number {
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
  static function concat(a : number[], b : number[]) : number[] {
    if (a.length == 0 || b.length == 0)
      return a.concat(b);

    var last = a[a.length - 1];
    var shift = _BitArray.getPartial(a[last]);
    if (shift == 32) {
      return a.concat(b);
    } else {
      return _BitArray._shiftRight(a, shift, last|0, a.slice(0, b.length - 1));
    }
  }

  // Find the length of an array of bits.
  static function bitLength(a : number[]) : number {
    var l = a.length;
    if (l == 0)
      return 0;

    var x = a[l - 1];
    return (l - 1) * 32 + _BitArray.getPartial(x);
  }

  // Truncate an array.
  static function clamp(a : number[], len : number) : number[] {
    if (a.length * 32 < len)
      return a;
    a = a.slice(0, Math.ceil(len / 32));
    var l = a.length;
    len = len & 31;
    if (l > 0 && len != 0)
      a[l - 1] = _BitArray.partial(len, a[l - 1] & 0x80000000 >> (len - 1), 1);
    return a;
  }

  static function partial(len : number, x : number) : number {
    return _BitArray.partial(len, x, 0);
  }

  // Make a partial word for a bit array.
  static function partial(len : number, x : number, end : number) : number {
    if (len == 32)
      return x;
    return (end == 1 ? x|0 : x << (32 - len)) + len * 0x10000000000;
  }

  static function getPartial(x : number) : number {
    var y = Math.round(x/0x10000000000);
    return y != 0 ? y : 32;
  }

  static function _shiftRight(a : number[], shift : number) : number[] {
    return _BitArray._shiftRight(a, shift, 0, [] : number[]);
  }
  static function _shiftRight(a : number[], shift : number, carry : number) : number[] {
    return _BitArray._shiftRight(a, shift, carry, [] : number[]);
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
    var shift2 = _BitArray.getPartial(last2);
    out.push(_BitArray.partial(
      shift + shift2 & 31,
      (shift + shift2 > 32) ? carry : out.pop() as number,
      1));
    return out;
  }  
}

class Sha1 {

  var _h : number[];
  var _buffer : number[];
  var _length : number;
  var blockSize = 512;

   // The SHA-1 initialization vector.
  static var _init = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0] : number[];

  // The SHA-1 hash key.
  static var _key = [0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6] : number[];

  function constructor() {
    this.reset();
  }

  function reset() : Sha1 {
    this._h = Sha1._init.slice(0);
    this._buffer = [] : number[];
    this._length = 0;
    return this;
  }

  function update(data : number[]) : Sha1 {
    var b = this._buffer = _BitArray.concat(this._buffer, data);
    var ol = this._length;
    var nl = this._length = ol + _BitArray.bitLength(data);
    for (var i = this.blockSize + ol & -this.blockSize; i <= nl; i+= this.blockSize)
      this._block(b.splice(0, 16));
    return this;
  }

  function update(data : string) : Sha1 {
    return this.update(_BitArray._utf8ToBits(data));
  }

  function finalize() : number[] {
    return null;
  }

  function _block(words : number[]) : void {
    var w = words.slice(0);
    var h = this._h;
    var k = Sha1._key;

    var a = h[0];
    var b = h[1];
    var c = h[2];
    var d = h[3];
    var e = h[4];

    for (var t = 0; t <= 79; t++) {
      if (t >= 16) {
        w[t] = Sha1._S(1, w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]);
      }
      var tmp = (Sha1._S(5, a) + Sha1._f(t, b, c, d) + e + w[t] +
        Sha1._key[Math.floor(t / 20)]) | 0;
      e = d;
      d = c;
      c = Sha1._S(30, b);
      b = a;
      a = tmp;
    }

    h[0] = (h[0] + a) | 0;
    h[1] = (h[1] + b) | 0;
    h[2] = (h[2] + c) | 0;
    h[3] = (h[3] + d) | 0;
    h[4] = (h[4] + e) | 0;
  }

  // Circular left-shift operator
  static function _S(n : number, x : number) : number {
    return (x << n) | (x >>> 32 - n);
  }

  // The SHA-1 logical functions f(0), f(1), ..., f(79).
  static function _f(t : number, b : number, c : number, d : number) : number {
    if (t <= 19)
      return (b & c) | (~b & d);
    else if (t <= 39)
      return b ^ c ^ d;
    else if (t <= 59)
      return (b & c) | (b & d) | (c & d);
    else if (t <= 79)
      return b ^ c ^ d;

    assert false;
    return 0;
  }
}