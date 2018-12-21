package org.scash.core.script.arithmetic
/**
 *   Copyright (c) 2016-2018 Chris Stewart (MIT License)
 *   Copyright (c) 2018 Flores Lorca (MIT License)
 */
import org.scash.core.script
import org.scash.core.script.constant._
import org.scash.core.script.control._
import org.scash.core.script.flag.ScriptFlagUtil
import org.scash.core.script.result._
import org.scash.core.util._
import org.scash.core.script._

import scalaz.{ -\/, \/, \/- }

import scala.annotation.tailrec

sealed abstract class ArithmeticInterpreter {
  private def logger = BitcoinSLogger.logger
  /** a is added to b. */
  def opAdd(p: ScriptProgram): ScriptProgram = {
    require(p.script.headOption.contains(OP_ADD), "Script top must be OP_ADD")
    binaryOp(p, (n1, n2) => \/-(n1 + n2))
  }

  /** Increments the stack top by 1. */
  def op1Add(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_1ADD), "Script top must be OP_1ADD")
    unaryOp(program, _ + ScriptNumber.one)
  }

  /** Decrements the stack top by 1. */
  def op1Sub(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_1SUB), "Script top must be OP_1SUB")
    unaryOp(program, _ - ScriptNumber.one)
  }

  /** b is subtracted from a. */
  def opSub(p: ScriptProgram): ScriptProgram = {
    require(p.script.headOption.contains(OP_SUB), "Script top must be OP_SUB")
    binaryOp(p, (n1, n2) => \/-(n2 - n1))
  }

  /** a is divided by b. */
  def opDiv(p: ScriptProgram): ScriptProgram = {
    require(p.script.headOption.contains(OP_DIV), "Script top must be OP_DIV")
    binaryOp(
      p,
      (n1, n2) =>
        if (n1 == ScriptNumber.zero)
          -\/(ScriptProgram(p, ScriptErrorDivByZero))
        else
          \/-(n2 / n1))
  }

  /** a mod of b */
  def opMod(p: ScriptProgram): ScriptProgram = {
    require(p.script.headOption.contains(OP_MOD), "Script top must be OP_MOD")
    binaryOp(
      p,
      (n1, n2) =>
        if (n1 == ScriptNumber.zero)
          -\/(ScriptProgram(p, ScriptErrorModByZero))
        else
          \/-(n2 % n1))
  }

  /** Takes the absolute value of the stack top. */
  def opAbs(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_ABS), "Script top must be OP_ABS")
    unaryOp(program, x => x match {
      case ScriptNumber.zero => ScriptNumber.zero
      case _: ScriptNumber => ScriptNumber(x.toLong.abs)
    })
  }

  /** Negates the stack top. */
  def opNegate(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_NEGATE), "Script top must be OP_NEGATE")
    unaryOp(program, -_)
  }

  /** If the input is 0 or 1, it is flipped. Otherwise the output will be 0. */
  def opNot(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_NOT), "Script top must be OP_NOT")
    unaryOp(program, _ => if (program.stackTopIsFalse) OP_TRUE else OP_FALSE)
  }

  /** Returns 0 if the input is 0. 1 otherwise. */
  def op0NotEqual(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_0NOTEQUAL), "Script top must be OP_0NOTEQUAL")
    unaryOp(program, x => if (x.isZero) OP_FALSE else OP_TRUE)
  }

  /** If both a and b are not 0, the output is 1. Otherwise 0. */
  def opBoolAnd(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_BOOLAND), "Script top must be OP_BOOLAND")
    binaryBoolOp(program, (x, y) => {
      val xIsFalse = (x == ScriptNumber.zero || x == OP_0)
      val yIsFalse = (y == ScriptNumber.zero || y == OP_0)
      if (xIsFalse || yIsFalse) false else true
    })
  }

  /** If a or b is not 0, the output is 1. Otherwise 0. */
  def opBoolOr(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_BOOLOR), "Script top must be OP_BOOLOR")
    binaryBoolOp(program, (x, y) => {
      if (x == y && (x == ScriptNumber.zero || x == OP_0)) false else true
    })
  }

  /** Returns 1 if the numbers are equal, 0 otherwise. */
  def opNumEqual(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_NUMEQUAL), "Script top must be OP_NUMEQUAL")
    binaryBoolOp(program, (x, y) => x.numEqual(y))
  }

  /** Same as [[OP_NUMEQUAL]], but runs [[OP_VERIFY]] afterward. */
  def opNumEqualVerify(program: ScriptProgram): ScriptProgram = {
    require(
      program.script.headOption.contains(OP_NUMEQUALVERIFY),
      "Script top must be OP_NUMEQUALVERIFY")
    if (program.stack.size < 2) {
      logger.error("OP_NUMEQUALVERIFY requires two stack elements")
      ScriptProgram(program, ScriptErrorInvalidStackOperation)
    } else {
      val numEqualProgram = ScriptProgram(program, program.stack, OP_NUMEQUAL :: program.script.tail)
      val numEqualResult = opNumEqual(numEqualProgram)
      numEqualResult match {
        case _: ExecutionInProgressScriptProgram =>
          val verifyProgram = ScriptProgram(numEqualResult, numEqualResult.stack, OP_VERIFY :: numEqualResult.script)
          val verifyResult = ControlOperationsInterpreter.opVerify(verifyProgram)
          verifyResult
        case _: PreExecutionScriptProgram | _: ExecutedScriptProgram =>
          numEqualResult
      }
    }
  }

  /** Returns 1 if the numbers are not equal, 0 otherwise. */
  def opNumNotEqual(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_NUMNOTEQUAL), "Script top must be OP_NUMNOTEQUAL")
    binaryBoolOp(program, (x, y) => x.toLong != y.toLong)
  }

  /** Returns 1 if a is less than b, 0 otherwise. */
  def opLessThan(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_LESSTHAN), "Script top must be OP_LESSTHAN")
    binaryBoolOp(program, (x, y) => y < x)
  }

  /** Returns 1 if a is greater than b, 0 otherwise. */
  def opGreaterThan(program: ScriptProgram): ScriptProgram = {
    require(program.script.headOption.contains(OP_GREATERTHAN), "Script top must be OP_GREATERTHAN")
    binaryBoolOp(program, (x, y) => y > x)
  }

  /** Returns 1 if a is less than or equal to b, 0 otherwise. */
  def opLessThanOrEqual(program: ScriptProgram): ScriptProgram = {
    require(
      program.script.headOption.contains(OP_LESSTHANOREQUAL),
      "Script top must be OP_LESSTHANOREQUAL")
    binaryBoolOp(program, (x, y) => y <= x)
  }

  /** Returns 1 if a is greater than or equal to b, 0 otherwise. */
  def opGreaterThanOrEqual(program: ScriptProgram): ScriptProgram = {
    require(
      program.script.headOption.contains(OP_GREATERTHANOREQUAL),
      "Script top must be OP_GREATERTHANOREQUAL")
    binaryBoolOp(program, (x, y) => y >= x)
  }

  /** Returns the smaller of a and b. */
  def opMin(p: ScriptProgram): ScriptProgram = {
    require(p.script.headOption.contains(OP_MIN), "Script top must be OP_MIN")
    binaryOp(p, (n1, n2) => \/-(if (n1 < n2) n1 else n2))
  }

  /** Returns the larger of a and b. */
  def opMax(p: ScriptProgram): ScriptProgram = {
    require(p.script.headOption.contains(OP_MAX), "Script top must be OP_MAX")
    binaryOp(p, (n1, n2) => \/-(if (n1 > n2) n1 else n2))
  }

  /** Returns 1 if x is within the specified range (left-inclusive), 0 otherwise. */
  def opWithin(program: ScriptProgram): ScriptProgram = {
    require(
      program.script.headOption.contains(OP_WITHIN),
      "Script top must be OP_WITHIN")
    if (program.stack.size < 3) {
      logger.error("OP_WITHIN requires at least 3 elements on the stack")
      ScriptProgram(program, ScriptErrorInvalidStackOperation)
    } else {
      val c = ScriptNumber(program.stack.head.bytes)
      val b = ScriptNumber(program.stack.tail.head.bytes)
      val a = ScriptNumber(program.stack.tail.tail.head.bytes)
      if (ScriptFlagUtil.requireMinimalData(program.flags) && (!BitcoinScriptUtil.isMinimalEncoding(c) ||
        !BitcoinScriptUtil.isMinimalEncoding(b) || !BitcoinScriptUtil.isMinimalEncoding(a))) {
        logger.error("The constant you gave us is not encoded in the shortest way possible")
        ScriptProgram(program, ScriptErrorUnknownError)
      } else if (isLargerThan4Bytes(c) || isLargerThan4Bytes(b) || isLargerThan4Bytes(a)) {
        //pretty sure that an error is thrown inside of CScriptNum which in turn is caught by interpreter.cpp here
        //https://github.com/bitcoin/bitcoin/blob/master/src/script/interpreter.cpp#L999-L1002
        logger.error("Cannot perform arithmetic operation on a number larger than 4 bytes, one of these three numbers is larger than 4 bytes: "
          + c + " " + b + " " + a)
        ScriptProgram(program, ScriptErrorUnknownError)
      } else {
        val isWithinRange = a >= b && a < c
        val newStackTop = if (isWithinRange) OP_TRUE else OP_FALSE
        ScriptProgram(program, newStackTop :: program.stack.tail.tail.tail, program.script.tail)
      }
    }
  }

  /**
   * Performs unary arithmetic operations
   */
  def unaryOp(p: ScriptProgram, op: ScriptNumber => ScriptNumber) =
    unaryScriptNumber(p)
      .map(n => ScriptProgram(p, op(n) :: p.stack.tail, p.script.tail))
      .merge

  /**
   * Performs binary arithmetic operations
   */
  def binaryOp(prog: ScriptProgram, op: (ScriptNumber, ScriptNumber) => ScriptProgram \/ ScriptNumber) = {
    (for {
      p <- script.checkBinary(prog)
      n <- binaryScriptNumbers(p)
      np <- op.tupled(n)
    } yield ScriptProgram(p, np :: p.stack.drop(2), p.script.tail)).merge
  }

  /**
   * Compares two script numbers with the given boolean operation
   * returns the program with either OP_FALSE or OP_TRUE on the stack top
   */
  def binaryBoolOp(program: ScriptProgram, op: (ScriptNumber, ScriptNumber) => Boolean): ScriptProgram = {
    binaryOp(program, (n1, n2) => \/-(if (op(n1, n2)) OP_TRUE else OP_FALSE))
  }

  /**
   * Returns the top object in the stack as ScriptNumber. Otherwise it will return
   * the program with the indicated Script error
   */
  @tailrec
  private def unaryScriptNumber(program: ScriptProgram): ScriptProgram \/ ScriptNumber = {
    program.stack.headOption match {
      case None =>
        logger.error("We need one stack element for performing a unary arithmetic operation")
        -\/(ScriptProgram(program, ScriptErrorInvalidStackOperation))
      case Some(s: ScriptNumber) =>
        if (ScriptFlagUtil.requireMinimalData(program.flags) && !BitcoinScriptUtil.isMinimalEncoding(s)) {
          logger.error("The number you gave us is not encoded in the shortest way possible")
          -\/(ScriptProgram(program, ScriptErrorMinimalData))
        } else if (isLargerThan4Bytes(s)) {
          logger.error("Cannot perform arithmetic operation on a number larger than 4 bytes, here is the number: " + s)
          -\/(ScriptProgram(program, ScriptErrorUnknownError))
        } else \/-(s)
      case Some(s: ScriptConstant) =>
        if (ScriptFlagUtil.requireMinimalData(program.flags) && !BitcoinScriptUtil.isMinimalEncoding(s)) {
          logger.error("The number you gave us is not encoded in the shortest way possible")
          -\/(ScriptProgram(program, ScriptErrorUnknownError))
        } else
          unaryScriptNumber(ScriptProgram(program, ScriptNumber(ScriptNumberUtil.toLong(s.hex)) :: program.stack.tail, ScriptProgram.Stack))
      case Some(_: ScriptToken) =>
        logger.error("Stack top must be a script number/script constant to perform an arithmetic operation")
        -\/(ScriptProgram(program, ScriptErrorUnknownError))
    }
  }

  /**
   * Returns the top two objects in the stack as ScriptNumbers. Otherwise it will return
   * the program with the indicated Script error
   */
  @tailrec
  private def binaryScriptNumbers(program: ScriptProgram): ScriptProgram \/ (ScriptNumber, ScriptNumber) = (program.stack.head, program.stack.tail.head) match {
    case (x: ScriptNumber, y: ScriptNumber) =>
      if (ScriptFlagUtil.requireMinimalData(program.flags) && (!BitcoinScriptUtil.isMinimalEncoding(x) || !BitcoinScriptUtil.isMinimalEncoding(y))) {
        logger.error("The constant you gave us is not encoded in the shortest way possible")
        -\/(ScriptProgram(program, ScriptErrorUnknownError))
      } else if (isLargerThan4Bytes(x) || isLargerThan4Bytes(y)) {
        logger.error("Cannot perform arithmetic operation on a number larger than 4 bytes, one of these two numbers is larger than 4 bytes: " + x + " " + y)
        -\/(ScriptProgram(program, ScriptErrorUnknownError))
      } else {
        \/-((x, y))
      }
    case (x: ScriptConstant, _: ScriptNumber) =>
      binaryScriptNumbers(ScriptProgram(program, ScriptNumber(x.hex) :: program.stack.tail, ScriptProgram.Stack))
    case (x: ScriptNumber, y: ScriptConstant) =>
      binaryScriptNumbers(ScriptProgram(program, x :: ScriptNumber(y.hex) :: program.stack.tail, ScriptProgram.Stack))
    case (x: ScriptConstant, y: ScriptConstant) =>
      binaryScriptNumbers(ScriptProgram(program, ScriptNumber(x.hex) :: ScriptNumber(y.hex) :: program.stack.tail.tail, ScriptProgram.Stack))
    case (_: ScriptToken, _: ScriptToken) =>
      logger.error("The top two stack items must be script numbers to perform an arithmetic operation")
      -\/(ScriptProgram(program, ScriptErrorUnknownError))
  }

  /**
   * This function checks if a number is <= 4 bytes in size
   * We cannot perform arithmetic operations on bitcoin numbers that are larger than 4 bytes.
   */
  private def isLargerThan4Bytes(scriptNumber: ScriptNumber): Boolean = scriptNumber.bytes.size > 4

}

object ArithmeticInterpreter extends ArithmeticInterpreter
