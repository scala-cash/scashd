package org.scash.core.crypto

import org.scash.core.currency.CurrencyUnits
import org.scash.core.number.UInt32
import org.scash.core.policy.Policy
import org.scash.core.protocol.script._
import org.scash.core.protocol.transaction._
import org.scash.core.script.crypto._
import org.scash.core.serializers.script.ScriptParser
import org.scash.core.util._
import org.scalatest.{ FlatSpec, MustMatchers }
import org.scash.core.script.crypto.BaseHashType

/**
 * Created by chris on 2/19/16.
 */
class TransactionSignatureSerializerTest extends FlatSpec with MustMatchers {
  private def logger = BitcoinSLogger.logger
  val scriptPubKey = BitcoinjConversions.toScriptPubKey(BitcoinJTestUtil.multiSigScript)

  "TransactionSignatureSerializer" must "correctly serialize an input that is being checked where another input in the same tx is using SIGHASH_ANYONECANPAY" in {
    val rawTx = "01000000020001000000000000000000000000000000000000000000000000000000000000000000004948304502203a0f5f0e1f2bdbcd04db3061d18f3af70e07f4f467cbc1b8116f267025f5360b022100c792b6e215afc5afc721a351ec413e714305cb749aae3d7fee76621313418df101010000000002000000000000000000000000000000000000000000000000000000000000000000004847304402205f7530653eea9b38699e476320ab135b74771e1c48b81a5d041e2ca84b9be7a802200ac8d1f40fb026674fe5a5edd3dea715c27baa9baca51ed45ea750ac9dc0a55e81ffffffff010100000000000000015100000000"
    val inputIndex = UInt32.zero
    val spendingTx = Transaction(rawTx)
    val scriptPubKeyFromString = ScriptParser.fromString("0x21 0x035e7f0d4d0841bcd56c39337ed086b1a633ee770c1ffdd94ac552a95ac2ce0efc CHECKSIG")
    val scriptPubKey = ScriptPubKey.fromAsm(scriptPubKeyFromString)

    val txSigComponent = TxSigComponent(
      spendingTx,
      inputIndex,
      TransactionOutput(CurrencyUnits.zero, scriptPubKey),
      Policy.standardFlags)
    val serializedTxForSig: String = BitcoinSUtil.encodeHex(
      TransactionSignatureSerializer.serializeLegacy(txSigComponent, SigHashType(BaseHashType.ALL)))

    //serialization is from bitcoin core
    serializedTxForSig must be("01000000020001000000000000000000000000000000000000000000000000000000000000000000002321035e7f0d4d0841bcd56c39337ed086b1a633ee770c1ffdd94ac552a95ac2ce0efcac0100000000020000000000000000000000000000000000000000000000000000000000000000000000ffffffff01010000000000000001510000000001000000")

  }

  it must "correctly serialize a tx for signing with multiple inputs using SIGHASH_SINGLE" in {
    //this is from a test case inside of tx_valid.json
    //https://github.com/bitcoin/bitcoin/blob/master/src/test/data/tx_valid.json#L96
    val rawTx = "010000000370ac0a1ae588aaf284c308d67ca92c69a39e2db81337e563bf40c59da0a5cf63000000006a4730440220360d20baff382059040ba9be98947fd678fb08aab2bb0c172efa996fd8ece9b702201b4fb0de67f015c90e7ac8a193aeab486a1f587e0f54d0fb9552ef7f5ce6caec032103579ca2e6d107522f012cd00b52b9a65fb46f0c57b9b8b6e377c48f526a44741affffffff7d815b6447e35fbea097e00e028fb7dfbad4f3f0987b4734676c84f3fcd0e804010000006b483045022100c714310be1e3a9ff1c5f7cacc65c2d8e781fc3a88ceb063c6153bf950650802102200b2d0979c76e12bb480da635f192cc8dc6f905380dd4ac1ff35a4f68f462fffd032103579ca2e6d107522f012cd00b52b9a65fb46f0c57b9b8b6e377c48f526a44741affffffff3f1f097333e4d46d51f5e77b53264db8f7f5d2e18217e1099957d0f5af7713ee010000006c493046022100b663499ef73273a3788dea342717c2640ac43c5a1cf862c9e09b206fcb3f6bb8022100b09972e75972d9148f2bdd462e5cb69b57c1214b88fc55ca638676c07cfc10d8032103579ca2e6d107522f012cd00b52b9a65fb46f0c57b9b8b6e377c48f526a44741affffffff0380841e00000000001976a914bfb282c70c4191f45b5a6665cad1682f2c9cfdfb88ac80841e00000000001976a9149857cc07bed33a5cf12b9c5e0500b675d500c81188ace0fd1c00000000001976a91443c52850606c872403c0601e69fa34b26f62db4a88ac00000000"
    val inputIndex = UInt32.zero
    val spendingTx = Transaction(rawTx)
    val scriptPubKeyFromString = ScriptParser.fromString("DUP HASH160 0x14 0xdcf72c4fd02f5a987cf9b02f2fabfcac3341a87d EQUALVERIFY CHECKSIG")
    val scriptPubKey = ScriptPubKey.fromAsm(scriptPubKeyFromString)
    val txSigComponent = TxSigComponent(
      spendingTx,
      inputIndex,
      TransactionOutput(CurrencyUnits.zero, scriptPubKey),
      Policy.standardFlags)
    val serializedTxForSig: String = BitcoinSUtil.encodeHex(
      TransactionSignatureSerializer.serializeLegacy(txSigComponent, SigHashType(BaseHashType.SINGLE)))
    //serialization is from bitcoin core
    serializedTxForSig must be("010000000370ac0a1ae588aaf284c308d67ca92c69a39e2db81337e563bf40c59da0a5cf63000000001976a914dcf72c4fd02f5a987cf9b02f2fabfcac3341a87d88acffffffff7d815b6447e35fbea097e00e028fb7dfbad4f3f0987b4734676c84f3fcd0e8040100000000000000003f1f097333e4d46d51f5e77b53264db8f7f5d2e18217e1099957d0f5af7713ee0100000000000000000180841e00000000001976a914bfb282c70c4191f45b5a6665cad1682f2c9cfdfb88ac0000000003000000")

  }

  it must "correctly serialize a tx for signing with the last input using SIGHASH_SINGLE" in {
    //this is from a test case inside of tx_valid.json
    //https://github.com/bitcoin/bitcoin/blob/master/src/test/data/tx_valid.json#L96
    val rawTx = "010000000370ac0a1ae588aaf284c308d67ca92c69a39e2db81337e563bf40c59da0a5cf63000000006a4730440220360d20baff382059040ba9be98947fd678fb08aab2bb0c172efa996fd8ece9b702201b4fb0de67f015c90e7ac8a193aeab486a1f587e0f54d0fb9552ef7f5ce6caec032103579ca2e6d107522f012cd00b52b9a65fb46f0c57b9b8b6e377c48f526a44741affffffff7d815b6447e35fbea097e00e028fb7dfbad4f3f0987b4734676c84f3fcd0e804010000006b483045022100c714310be1e3a9ff1c5f7cacc65c2d8e781fc3a88ceb063c6153bf950650802102200b2d0979c76e12bb480da635f192cc8dc6f905380dd4ac1ff35a4f68f462fffd032103579ca2e6d107522f012cd00b52b9a65fb46f0c57b9b8b6e377c48f526a44741affffffff3f1f097333e4d46d51f5e77b53264db8f7f5d2e18217e1099957d0f5af7713ee010000006c493046022100b663499ef73273a3788dea342717c2640ac43c5a1cf862c9e09b206fcb3f6bb8022100b09972e75972d9148f2bdd462e5cb69b57c1214b88fc55ca638676c07cfc10d8032103579ca2e6d107522f012cd00b52b9a65fb46f0c57b9b8b6e377c48f526a44741affffffff0380841e00000000001976a914bfb282c70c4191f45b5a6665cad1682f2c9cfdfb88ac80841e00000000001976a9149857cc07bed33a5cf12b9c5e0500b675d500c81188ace0fd1c00000000001976a91443c52850606c872403c0601e69fa34b26f62db4a88ac00000000"
    val inputIndex = UInt32(2)
    val spendingTx = Transaction(rawTx)
    val scriptPubKeyFromString = ScriptParser.fromString("DUP HASH160 0x14 0xdcf72c4fd02f5a987cf9b02f2fabfcac3341a87d EQUALVERIFY CHECKSIG")
    val scriptPubKey = ScriptPubKey.fromAsm(scriptPubKeyFromString)
    val txSigComponent = TxSigComponent(
      spendingTx,
      inputIndex,
      TransactionOutput(CurrencyUnits.zero, scriptPubKey),
      Policy.standardFlags)
    val serializedTxForSig: String = BitcoinSUtil.encodeHex(
      TransactionSignatureSerializer.serializeLegacy(txSigComponent, SigHashType(BaseHashType.SINGLE)))
    //serialization is from bitcoin core
    serializedTxForSig must be("010000000370ac0a1ae588aaf284c308d67ca92c69a39e2db81337e563bf40c59da0a5cf630000000000000000007d815b6447e35fbea097e00e028fb7dfbad4f3f0987b4734676c84f3fcd0e8040100000000000000003f1f097333e4d46d51f5e77b53264db8f7f5d2e18217e1099957d0f5af7713ee010000001976a914dcf72c4fd02f5a987cf9b02f2fabfcac3341a87d88acffffffff03ffffffffffffffff00ffffffffffffffff00e0fd1c00000000001976a91443c52850606c872403c0601e69fa34b26f62db4a88ac0000000003000000")

  }

  it must "correctly serialize a tx which spends an input that pushes using a PUSHDATA1 that is negative when read as signed" in {
    //this is from a test case inside of tx_valid.json
    //https://github.com/bitcoin/bitcoin/blob/master/src/test/data/tx_valid.json#L102
    val rawTx = "0100000001482f7a028730a233ac9b48411a8edfb107b749e61faf7531f4257ad95d0a51c5000000008b483045022100bf0bbae9bde51ad2b222e87fbf67530fbafc25c903519a1e5dcc52a32ff5844e022028c4d9ad49b006dd59974372a54291d5764be541574bb0c4dc208ec51f80b7190141049dd4aad62741dc27d5f267f7b70682eee22e7e9c1923b9c0957bdae0b96374569b460eb8d5b40d972e8c7c0ad441de3d94c4a29864b212d56050acb980b72b2bffffffff0180969800000000001976a914e336d0017a9d28de99d16472f6ca6d5a3a8ebc9988ac00000000"
    val inputIndex = UInt32.zero
    val spendingTx = Transaction(rawTx)
    val scriptPubKeyFromString = ScriptParser.fromString("0x4c 0xae 0x606563686f2022553246736447566b58312b5a536e587574356542793066794778625456415675534a6c376a6a334878416945325364667657734f53474f36633338584d7439435c6e543249584967306a486956304f376e775236644546673d3d22203e20743b206f70656e73736c20656e63202d7061737320706173733a5b314a564d7751432d707269766b65792d6865785d202d64202d6165732d3235362d636263202d61202d696e207460 DROP DUP HASH160 0x14 0xbfd7436b6265aa9de506f8a994f881ff08cc2872 EQUALVERIFY CHECKSIG")
    val scriptPubKey = ScriptPubKey.fromAsm(scriptPubKeyFromString)
    val txSigComponent = TxSigComponent(
      spendingTx,
      inputIndex,
      TransactionOutput(CurrencyUnits.zero, scriptPubKey),
      Policy.standardFlags)
    val serializedTxForSig: String = BitcoinSUtil.encodeHex(
      TransactionSignatureSerializer.serializeLegacy(txSigComponent, SigHashType(BaseHashType.ALL)))
    serializedTxForSig must be("0100000001482f7a028730a233ac9b48411a8edfb107b749e61faf7531f4257ad95d0a51c500000000ca4cae606563686f2022553246736447566b58312b5a536e587574356542793066794778625456415675534a6c376a6a334878416945325364667657734f53474f36633338584d7439435c6e543249584967306a486956304f376e775236644546673d3d22203e20743b206f70656e73736c20656e63202d7061737320706173733a5b314a564d7751432d707269766b65792d6865785d202d64202d6165732d3235362d636263202d61202d696e2074607576a914bfd7436b6265aa9de506f8a994f881ff08cc287288acffffffff0180969800000000001976a914e336d0017a9d28de99d16472f6ca6d5a3a8ebc9988ac0000000001000000")
  }

  it must "correctly hash a tx with one input SIGHASH_ALL and one SIGHASH_ANYONECANPAY, but we set the _ANYONECANPAY sequence number, invalidating the SIGHASH_ALL signature" in {
    val rawTx = "01000000020001000000000000000000000000000000000000000000000000000000000000000000004948304502203a0f5f0e1f2bdbcd04db3061d18f3af70e07f4f467cbc1b8116f267025f5360b022100c792b6e215afc5afc721a351ec413e714305cb749aae3d7fee76621313418df10101000000000200000000000000000000000000000000000000000000000000000000000000000000484730440220201dc2d030e380e8f9cfb41b442d930fa5a685bb2c8db5906671f865507d0670022018d9e7a8d4c8d86a73c2a724ee38ef983ec249827e0e464841735955c707ece98101000000010100000000000000015100000000"
    val inputIndex = UInt32.zero
    val spendingTx = Transaction(rawTx)
    val scriptPubKeyFromString = ScriptParser.fromString("0x21 0x035e7f0d4d0841bcd56c39337ed086b1a633ee770c1ffdd94ac552a95ac2ce0efc CHECKSIG")
    val scriptPubKey = ScriptPubKey.fromAsm(scriptPubKeyFromString)
    val txSigComponent = TxSigComponent(
      spendingTx,
      inputIndex,
      TransactionOutput(CurrencyUnits.zero, scriptPubKey),
      Policy.standardFlags)
    val serializedTxForSig: String = BitcoinSUtil.encodeHex(
      TransactionSignatureSerializer.serializeLegacy(txSigComponent, SigHashType(BaseHashType.ALL)))
    serializedTxForSig must be("01000000020001000000000000000000000000000000000000000000000000000000000000000000002321035e7f0d4d0841bcd56c39337ed086b1a633ee770c1ffdd94ac552a95ac2ce0efcac01000000000200000000000000000000000000000000000000000000000000000000000000000000000100000001010000000000000001510000000001000000")

  }
}
