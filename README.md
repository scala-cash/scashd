[![Build Status](https://travis-ci.org/scala-cash/scash.svg?branch=master)](https://travis-ci.org/scala-cash/scash) [![Coverage Status](https://coveralls.io/repos/github/scala-cash/scash/badge.svg)](https://coveralls.io/github/scala-cash/scash) [![Gitter chat](https://badges.gitter.im/gitterHQ/gitter.png)](https://gitter.im/scash)

# scash

This is the core functionality of scash.

This repostitory includes the following functionality:
  - Native Scala objects for various protocol types ([transactions](https://github.com/scala-cash/scash/blob/master/core/src/main/scala/org/scash/core/protocol/transaction/Transaction.scala), [inputs](https://github.com/scala-cash/scash/blob/master/core/src/main/scala/org/scash/core/protocol/transaction/TransactionInput.scala), [outputs](https://github.com/scala-cash/scash/blob/master/core/src/main/scala/org/scash/core/protocol/transaction/TransactionOutput.scala), [scripts signatures](https://github.com/scala-cash/scash/blob/master/core/src/main/scala/org/scash/core/protocol/script/ScriptSignature.scala), [scriptpubkeys](https://github.com/scala-cash/scash/blob/master/core/src/main/scala/org/scash/core/protocol/script/ScriptPubKey.scala))
  - [Serializers and deserializers for bitcoin data structures mentioned above](https://github.com/scala-cash/scash/blob/master/core/src/main/scala/org/scash/core/src/main/scala/org/scash/core/serializers)
  - [An implementation of Bitcoin's Script programming language](https://github.com/scala-cash/scash/blob/master/core/src/main/scala/org/scash/core/script) 
    - Passes all tests found in Bitcoin ABC's regression test suite called [script_test.json](https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/test/data/script_tests.jsonn)
    - Passes all tests inside of Bitcoin ABC's transaction regression test suite [tx_valid.json](https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/test/data/tx_valid.json) / [tx_invalid.json](https://github.com/Bitcoin-ABC/bitcoin-abc/blob/master/src/test/data/tx_invalid.json) / 
    [sighash.json](https://github.com/bitcoin/bitcoin/blob/master/src/test/data/sighash.json)
  - Integration with [bitcoin core's optimized secp256k1](https://github.com/bitcoin-core/secp256k1/) library
  - A robust set of [generators](https://github.com/scala-cash/scash/tree/master/core-gen/src/test/scala/org/scash/core/gen), which are used in property based testing
    - These are extremely useful for testing bitcoin applications
    - Here is an example of a specification for our [ECPrivateKey](https://github.com/scala-cash/scash/blob/master/core-test/src/test/scala/org/scash/core/crypto/ECPrivateKeyTest.scala)
  - 90% test coverage throughout the codebase to ensure high quality code. 
  - Functions documented with Scaladocs for user friendliness

# Design Principles
  - Immutable data structures everywhere
  - Functional Programming following these 3 properties (WIP):
    1. Totality
    2. Determinism
    3. No Side Effects

  - Algebraic Data Types to allow the compiler to check for exhaustiveness on match statements
  - Using [property based testing](http://www.scalatest.org/user_guide/property_based_testing) to test robustness of code 
 
# Setting up libsecp256k1

libsecp256k1 needs to be built with the java interface enabled. Use the following commands to build secp256k1 with jni enabled. [Here is the official documentation for doing this in secp256k1](https://github.com/bitcoin-core/secp256k1/blob/master/src/java/org/bitcoin/NativeSecp256k1.java#L35)
```
$ cd secp256k1
$ sh autogen.sh && ./configure --enable-jni --enable-experimental --enable-module-ecdh && make
$ sudo make install #optional, this installs the lib on your system
```

Now you should be able to run secp256k1 with something like this. Or you can just copy `libsecp256k1.so` to your system library path. 
```
$ sbt -Djava.library.path=/usr/local/lib test
```

# TODO
  - full bitcoin cash support
  - Nov 15/18 Hard fork
  - introduce FP friendly libraries
  - implement cashaddr
  - spv node [`scashspv`](https://github.com/scala-cash/scashspv)

# Creating fat jar

Here is how you build a scash fat jar file. Note this command will run the entire test suite in scash.

```scala
$ sbt assembly
...
[info] Merging files...
...
[info] Done packaging.

```

# Examples

Every bitcoin protocol data structure (and some other data structures) extends [`NetworkElement`](https://github.com/scala-cash/scash/blob/master/core/src/main/scala/org/scash/core/protocol/NetworkElement.scala). NetworkElement provides easier methods to convert the data structure to hex or a byte representation. When paired with our [`Factory`](https://github.com/scala-cash/scash/blob/master/core/src/main/scala/org/scash/core/util/Factory.scala) we can easily serialize and deserialize data structures. Most data structures have companion objects that extends `Factory` to be able to easily create protocol data structures. An example of this is the [`ScriptPubKey`](https://github.com/scala-cash/scash/blob/master/core/src/main/scala/org/scash/core/protocol/script/ScriptPubKey.scala) companion object. You can use this companion object to create a SPK from hex or a byte array.

Transactions are run through the interpreter to check the validity of the Transaction. These are packaged up into an object called ScriptProgram, which contains the following:
  - The transaction that is being checked
  - The specific input index that it is checking
  - The scriptPubKey for the crediting transaction
  - The flags used to verify the script

Here is an example of a transaction spending a scriptPubKey which is correctly evaluated with our interpreter implementation:

```scala
sbt console
...

scala> import org.scash.core.protocol.script._
import org.scash.core.protocol.script._

scala> import org.scash.core.protocol.transaction._
import org.scash.core.protocol.transaction._

scala> import org.scash.core.script._
import org.scash.core.script._

scala> import org.scash.core.script.interpreter._
import org.scash.core.script.interpreter._

scala> import org.scash.core.policy._
import org.scash.core.policy._

scala> val hexTx = hex"0100000000001ccf3...."
hexTx: ByteVector = ByteVector(...)
scala> val spendingTx = Transaction(hexTx)
spendingTx: Transaction = TransactionImpl(1,List(TransactionInputImpl(TransactionOutPointImpl(b30d3148927f620f5b1228ba941c211fdabdae75d0ba0b688a58accbf018f3cc,0),P2PKHScriptSignatureImpl(4830450221008337ce3ce0c6ac0ab72509f889c1d52701817a2362d6357457b63e3bdedc0c0602202908963b9cf1a095ab3b34b95ce2bc0d67fb0f19be1cc5f7b3de0b3a325629bf01210241d746ca08da0a668735c3e01c1fa02045f2f399c5937079b6434b5a31dfe353,List(BytesToPushOntoStackImpl(72), ScriptConstantImpl(30450221008337ce3ce0c6ac0ab72509f889c1d52701817a2362d6357457b63e3bdedc0c0602202908963b9cf1a095ab3b34b95ce2bc0d67fb0f19be1cc5f7b3de0b3a325629bf01), BytesToPushOntoStackImpl(33), ScriptConstantImpl(0241d746ca08da0a668735c3e01c1fa02045f2f399c5937079b6434b5a31dfe353))),4294967295)),List(TransactionOutputImpl(8...
scala> val scriptPubKey = ScriptPubKey("76a91431a420903c05a0a7de2de40c9f02ebedbacdc17288ac")
scriptPubKey: ScriptPubKey = P2PKHScriptPubKeyImpl(76a91431a420903c05a0a7de2de40c9f02ebedbacdc17288ac,List(OP_DUP, OP_HASH160, BytesToPushOntoStackImpl(20), ScriptConstantImpl(31a420903c05a0a7de2de40c9f02ebedbacdc172), OP_EQUALVERIFY, OP_CHECKSIG))

scala> val inputIndex = 0
inputIndex: Int = 0

scala> val program = ScriptProgram(spendingTx,scriptPubKey,inputIndex, Policy.standardScriptVerifyFlags)
program: PreExecutionScriptProgram = PreExecutionScriptProgramImpl(TransactionSignatureComponentImpl(TransactionImpl(1,List(TransactionInputImpl(TransactionOutPointImpl(b30d3148927f620f5b1228ba941c211fdabdae75d0ba0b688a58accbf018f3cc,0),P2PKHScriptSignatureImpl(4830450221008337ce3ce0c6ac0ab72509f889c1d52701817a2362d6357457b63e3bdedc0c0602202908963b9cf1a095ab3b34b95ce2bc0d67fb0f19be1cc5f7b3de0b3a325629bf01210241d746ca08da0a668735c3e01c1fa02045f2f399c5937079b6434b5a31dfe353,List(BytesToPushOntoStackImpl(72), ScriptConstantImpl(30450221008337ce3ce0c6ac0ab72509f889c1d52701817a2362d6357457b63e3bdedc0c0602202908963b9cf1a095ab3b34b95ce2bc0d67fb0f19be1cc5f7b3de0b3a325629bf01), BytesToPushOntoStackImpl(33), ScriptConstantImpl(0241d746ca08da0a668735c3e01c1fa02045f2f399c5937079...
scala> ScriptInterpreter.run(program)
res0: ScriptResult = ScriptOk
```
# Running tests

To run the entire test suite all you need to do is run the following command
```scala 
sbt test
...
[info] All tests passed.
[info] Passed: Total 909, Failed 0, Errors 0, Passed 909

```

To run a specific suite of tests you can specify the suite name in the following way
```scala
sbt
> testOnly *ScriptInterpreterTest*
...
[info] All tests passed.
>
```
# Stand alone SPV Node

Please see our other project [`scashspv`](https://github.com/scala-cash/scashspv)
