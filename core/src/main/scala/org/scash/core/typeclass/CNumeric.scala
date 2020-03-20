package org.scash.core.typeclass

trait CNumeric[A] {
  self =>
  def andMask: BigInt
  def num: A => BigInt
  def apply: BigInt => A

  def sum[A1: CNumeric](a: A, a1: A1): A = checkResult(num(a) + CNumeric[A1].num(a1))
  def sub[A1: CNumeric](a: A, a1: A1): A = checkResult(num(a) - CNumeric[A1].num(a1))
  def mul[A1: CNumeric](a: A, a1: A1): A = checkResult(num(a) * CNumeric[A1].num(a1))

  def gt[A1: CNumeric](a: A, a1: A1): Boolean  = num(a) > CNumeric[A1].num(a1)
  def gte[A1: CNumeric](a: A, a1: A1): Boolean = num(a) >= CNumeric[A1].num(a1)
  def lt[A1: CNumeric](a: A, a1: A1): Boolean  = num(a) < CNumeric[A1].num(a1)
  def lte[A1: CNumeric](a: A, a1: A1): Boolean = num(a) <= CNumeric[A1].num(a1)

  def or[A1: CNumeric](a: A, a1: A1): A  = checkResult(num(a) | CNumeric[A1].num(a1))
  def and[A1: CNumeric](a: A, a1: A1): A = checkResult(num(a) & CNumeric[A1].num(a1))
  def xor[A1: CNumeric](a: A, a1: A1): A = checkResult(num(a) ^ CNumeric[A1].num(a1))

  def negative(a: A): A = apply(-num(a))

  def shiftL(a: A, a1: A): A =
    checkIfInt(a, a1)((n, n1) => (num(n) << num(n1).toInt) & andMask)

  //this check is for weird behavior with the jvm and shift rights
  //https://stackoverflow.com/questions/47519140/bitwise-shift-right-with-long-not-equaling-zero/47519728#47519728
  def shiftR(a: A, a1: A): A =
    if (num(a1).toLong > 63) apply(0)
    else checkIfInt(a, a1)((n, n1) => num(n) >> num(n1).toInt)

  def toLong(a: A): Long = num(a).bigInteger.longValueExact()
  def toInt(a: A): Int   = num(a).bigInteger.intValueExact()

  private def checkResult(result: BigInt): A = {
    require((result & andMask) == result, "Result was out of bounds, got: " + result)
    apply(result)
  }

  /** Checks if the given number is within range of a Int */
  private def checkIfInt(a: A, a1: A)(f: (A, A) => BigInt): A = {
    require(num(a1) >= Int.MaxValue || num(a1) <= Int.MinValue, "Num was not in range of int, got: " + a1)
    apply(f(a, a1))
  }
}

object CNumeric {
  def apply[A](implicit n: CNumeric[A]): CNumeric[A] = n

  def apply[A](mask: BigInt)(n: A => BigInt, app: BigInt => A): CNumeric[A] = new CNumeric[A] {
    def andMask = mask
    def num     = n
    def apply   = app
  }
}

trait NumericSyntax {
  implicit class NumericSyntaxOps[A: CNumeric](a: A) {
    def +[A1: CNumeric](num: A1): A        = CNumeric[A].sum(a, num)
    def -[A1: CNumeric](num: A1): A        = CNumeric[A].sub(a, num)
    def *[A1: CNumeric](num: A1): A        = CNumeric[A].mul(a, num)
    def >[A1: CNumeric](num: A1): Boolean  = CNumeric[A].gt(a, num)
    def >=[A1: CNumeric](num: A1): Boolean = CNumeric[A].gte(a, num)
    def <[A1: CNumeric](num: A1): Boolean  = CNumeric[A].lt(a, num)
    def <=[A1: CNumeric](num: A1): Boolean = CNumeric[A].lte(a, num)

    def <<(num: Int): A = CNumeric[A].shiftL(a, CNumeric[A].apply(BigInt(num)))
    def >>(num: Int): A = CNumeric[A].shiftR(a, CNumeric[A].apply(BigInt(num)))

    def <<(num: A): A = CNumeric[A].shiftL(a, num)
    def >>(num: A): A = CNumeric[A].shiftR(a, num)

    def |(num: A): A = CNumeric[A].or(a, num)
    def &(num: A): A = CNumeric[A].and(a, num)
    def ^(num: A): A = CNumeric[A].xor(a, num)
    def unary_- : A  = CNumeric[A].negative(a)
  }
}
