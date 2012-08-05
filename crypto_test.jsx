import "js.jsx";
import "crypto.jsx";
import "test_data.jsx";

native class check {
  static function ok(p : boolean, m : string) : void;
  static function ok(p : boolean) : void;
}

class _Main {
  static function main(args : string[]) : void {
    Sha256TestData.VECTORS.forEach((v) -> {
      var a = Crypto.toHex(Crypto.sha256(v[0]));
      check.ok(a == v[1]);
    });
    log 'Holy Crap! All Tests Passed!';
  }
}
