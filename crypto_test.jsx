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
      var a = Crypto.hex(new Sha256.update(v[0]).finalize());
      log v[0];
      log a;
      log v[1];
      log '';
      check.ok(a == v[1]);
    });
  }
}
