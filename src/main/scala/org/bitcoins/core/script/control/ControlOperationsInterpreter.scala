package org.bitcoins.core.script.control

import org.bitcoins.core.protocol.script.SigVersionWitnessV0
import org.bitcoins.core.script.ScriptProgram
import org.bitcoins.core.script.constant._
import org.bitcoins.core.script.flag.ScriptFlagUtil
import org.bitcoins.core.script.result._
import org.bitcoins.core.util._

import scala.annotation.tailrec

/**
 * Created by chris on 1/6/16.
 */
trait ControlOperationsInterpreter {
  private def logger = BitcoinSLogger.logger
  /** If the top stack value is not 0, the statements are executed. The top stack value is removed. */
  def opIf(program : ScriptProgram) : ScriptProgram = {
    require(program.script.headOption.contains(OP_IF), "Script top was not OP_IF")
    val sigVersion = program.txSignatureComponent.sigVersion
    val flags = program.flags
    val minimalIfEnabled = ScriptFlagUtil.minimalIfEnabled(flags)
    val binaryTree = parseBinaryTree(program.script)
    val stackTop = program.stack.headOption
    logger.debug("Parsed binary tree: " + binaryTree)
    if (!checkMatchingOpIfOpNotIfOpEndIf(program.originalScript)) {
      logger.error("We do not have a matching OP_ENDIF for every OP_IF we have")
      ScriptProgram(program,ScriptErrorUnbalancedConditional)
    } else if (program.stack.isEmpty) {
      logger.error("We do not have any stack elements for our OP_IF")
      ScriptProgram(program,ScriptErrorUnbalancedConditional)
    } else if (sigVersion == SigVersionWitnessV0 && minimalIfEnabled
      && (stackTop.get.bytes.size > 1 ||
      (stackTop.get.bytes.size == 1 && stackTop.get.bytes.head != 1))) {
      //see: https://github.com/bitcoin/bitcoin/blob/528472111b4965b1a99c4bcf08ac5ec93d87f10f/src/script/interpreter.cpp#L447-L452
      //https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2016-August/013014.html
      logger.error("OP_IF argument was not minimally encoded, got: " + stackTop)
      ScriptProgram(program, ScriptErrorMinimalIf)
    } else if (program.stackTopIsTrue) {
      logger.debug("OP_IF stack top was true")
      logger.debug("Stack top: " + program.stack)
      //if the left branch contains and OP_IF & OP_ENDIF there must be a nested OP_IF
      //remove OP_ELSE from binary tree
      val newTreeWithoutOpElse = removeFirstOpElse(binaryTree)
      val newScript = newTreeWithoutOpElse.toList
      logger.debug("New script after removing OP_ELSE branch " + newScript.tail)
      logger.debug("New stack after removing OP_ELSE branch: " + program.stack.tail)
      ScriptProgram(program, program.stack.tail,newScript.tail)
    }  else {
      logger.debug("OP_IF stack top was false")
      //remove the OP_IF
      val scriptWithoutOpIf : BinaryTree[ScriptToken] = removeFirstOpIf(binaryTree)
      ScriptProgram(program, program.stack.tail,scriptWithoutOpIf.toList)
    }
  }

  /** If the top stack value is 0, the statements are executed. The top stack value is removed. */
  def opNotIf(program : ScriptProgram) : ScriptProgram = {
    //TODO: Try and reduce this down to using OP_IF by inverting the stack top
    require(program.script.headOption.contains(OP_NOTIF), "Script top was not OP_NOTIF")
    val binaryTree = parseBinaryTree(program.script)
    val sigVersion = program.txSignatureComponent.sigVersion
    val flags = program.flags
    val minimalIfEnabled = ScriptFlagUtil.minimalIfEnabled(flags)
    val stackTop = program.stack.headOption
    logger.debug("Parsed binary tree: " + binaryTree)
    if (!checkMatchingOpIfOpNotIfOpEndIf(program.originalScript)) {
      logger.error("We do not have a matching OP_ENDIF for every OP_NOTIF we have")
      ScriptProgram(program,ScriptErrorUnbalancedConditional)
    } else if (program.stack.isEmpty) {
      logger.error("We do not have any stack elements for our OP_NOTIF")
      ScriptProgram(program,ScriptErrorUnbalancedConditional)
    } else if (sigVersion == SigVersionWitnessV0 && minimalIfEnabled
      && (stackTop.get.bytes.size > 1 ||
      (stackTop.get.bytes.size == 1 && stackTop.get.bytes.head != 1))) {
      //see: https://github.com/bitcoin/bitcoin/blob/528472111b4965b1a99c4bcf08ac5ec93d87f10f/src/script/interpreter.cpp#L447-L452
      //https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2016-August/013014.html
      logger.error("OP_NOTIF argument was not minimally encoded, got: " + stackTop)
      ScriptProgram(program, ScriptErrorMinimalIf)
    } else if (program.stackTopIsTrue) {
      //remove the OP_NOTIF
      val scriptWithoutOpIf : BinaryTree[ScriptToken] = removeFirstOpIf(binaryTree)
      ScriptProgram(program, program.stack.tail,scriptWithoutOpIf.toList)
    } else {
      //if the left branch contains and OP_NOTIF & OP_ENDIF there must be a nested OP_IF or OP_NOTIF
      //remove OP_ELSE from binary tree
      val newTreeWithoutOpElse = removeFirstOpElse(binaryTree)
      val newScript = newTreeWithoutOpElse.toList
      ScriptProgram(program, program.stack.tail,newScript.tail)
    }
  }

  /** Evaluates the [[OP_ELSE]] operator. */
  def opElse(program : ScriptProgram) : ScriptProgram = {
    require(program.script.headOption.contains(OP_ELSE), "First script opt must be OP_ELSE")
    if (!program.script.tail.contains(OP_ENDIF)) {
      logger.error("OP_ELSE does not have a OP_ENDIF")
      ScriptProgram(program,ScriptErrorUnbalancedConditional)
    } else {
      val tree = parseBinaryTree(program.script)
      val treeWithNextOpElseRemoved = tree match {
        case Empty => Empty
        case leaf : Leaf[ScriptToken] => leaf
        case node : Node[ScriptToken] =>
          if (node.r.value == Some(OP_ELSE)) {
            val replacementTree = node.r.left.getOrElse(Empty).findFirstDFS[ScriptToken](OP_ENDIF)().getOrElse(Empty)
            val replacementNode = replacementTree match {
              case Empty => Empty
              case leaf : Leaf[ScriptToken] => Node(leaf.v, Empty, node.r.right.getOrElse(Empty))
              case node1 : Node[ScriptToken] => Node(node1.v,node1.l,node.r.right.getOrElse(Empty))
            }
            Node(node.v,node.l,replacementNode)
          }
          else node
      }
      ScriptProgram(program, program.stack,treeWithNextOpElseRemoved.toList.tail)
    }
  }

  /** Evaluates an [[OP_ENDIF]] operator. */
  def opEndIf(program : ScriptProgram) : ScriptProgram = {
    require(program.script.headOption.contains(OP_ENDIF), "Script top must be OP_ENDIF")
    if (!checkMatchingOpIfOpNotIfOpEndIf(program.originalScript)) {
      //means we do not have a matching OP_IF for our OP_ENDIF
      logger.error("We do not have a matching OP_IF/OP_NOTIF for every OP_ENDIF we have")
      ScriptProgram(program,ScriptErrorUnbalancedConditional)
    } else ScriptProgram(program, program.stack,program.script.tail)
  }

  /** Marks transaction as invalid. A standard way of attaching extra data to transactions is to add a zero-value output
   * with a [[org.bitcoins.core.protocol.script.ScriptPubKey]] consisting of [[OP_RETURN]] followed by exactly one pushdata op. Such outputs are provably unspendable,
   * reducing their cost to the network. Currently it is usually considered non-standard (though valid) for a transaction to
   * have more than one OP_RETURN output or an OP_RETURN output with more than one pushdata op. */
  def opReturn(program : ScriptProgram) : ScriptProgram = {
    require(program.script.headOption.contains(OP_RETURN))
    ScriptProgram(program,ScriptErrorOpReturn)
  }

  /** Marks [[org.bitcoins.core.protocol.transaction.Transaction]] as invalid if top stack value is not true. */
  def opVerify(program : ScriptProgram) : ScriptProgram = {
    require(program.script.headOption.contains(OP_VERIFY), "Script top must be OP_VERIFY")
    program.stack.nonEmpty match {
      case true =>
        logger.debug("Stack for OP_VERIFY: " + program.stack)
        if (program.stackTopIsFalse) ScriptProgram(program,ScriptErrorVerify)
        else ScriptProgram(program, program.stack.tail,program.script.tail)
      case false =>
        logger.error("OP_VERIFY requires an element to be on the stack")
        ScriptProgram(program,ScriptErrorInvalidStackOperation)
    }
  }

  /** Parses a list of [[ScriptToken]]s into its corresponding [[BinaryTree]] */
  def parseBinaryTree(script : List[ScriptToken]) : BinaryTree[ScriptToken] = {
    //@tailrec
    def l(remaining: List[ScriptToken], parentTree: BinaryTree[ScriptToken]): (BinaryTree[ScriptToken], List[ScriptToken]) = {
      if (remaining.isEmpty) (parentTree,Nil)
      else {
        logger.debug("remaining: " + remaining + " parentTree: " + parentTree)
        if (parentTree.right.isDefined && parentTree.right.get.value == Some(OP_ELSE)) {
          //for the case of OP_IF OP_1 OP_ELSE OP_2 OP_ELSE OP_3 ... OP_ELSE OP_N OP_ENDIF
/*          val (elseTree,newRemaining) = loop(remaining,parentTree.right.get)
          val n = Node(parentTree.value.get, parentTree.left.getOrElse(Empty), elseTree)
          logger.debug("n: " + n)
          l(newRemaining,n)*/

          val (elseTree,newRemaining) = l(remaining, parentTree.right.getOrElse(Empty))
          val n = Node(parentTree.value.get, parentTree.left.getOrElse(Empty), elseTree)
          (n,newRemaining)
        } else {
          val (tree, newRemaining) = loop(remaining,parentTree)
          l(newRemaining,tree)
        }


      }
    }
    val (t, remaining) = l(script,Empty)
    require(remaining.isEmpty, "Should not have any script tokens after parsing a binary tree, got: " + remaining)
    t
  }

  /** The loop that parses a list of [[ScriptToken]]s into a [[BinaryTree]]. */
  private def loop(script : List[ScriptToken], tree : BinaryTree[ScriptToken]): (BinaryTree[ScriptToken], List[ScriptToken]) = {
/*    logger.debug("Script : " + script) */
    logger.debug("Tree: " + tree)
    logger.debug("script: " + (if (script.nonEmpty) script else Nil))
    script match {
      case OP_ENDIF :: t =>
        //require(t.isEmpty, "Must not have any tail after parsing an OP_ENDIF, got: "+ t)
        require(tree.value.isDefined && Seq(OP_IF,OP_NOTIF,OP_ELSE).contains(tree.value.get),
          "Can only insert an OP_ENDIF on a tree root of OP_IF/NOTIF/ELSE, got: " + tree.value)
        //require(tree.right == Some(Empty), "Must have an empty right branch when inserting an OP_ENDIF onto our btree, got: " + tree.right)
        //base case, doesn't matter what we return since call insertSubTree(tree,Leaf(OP_ENDIF))
        val ifTree = insertSubTree(tree,Leaf(OP_ENDIF))
        logger.debug("ifTree: " + ifTree + " t: " + t)
        (ifTree,t)
      case h :: t if (h == OP_IF || h == OP_NOTIF) =>
        //find last OP_ENDIF in t
/*        val endifs = t.zipWithIndex.filter(_._1 == OP_ENDIF)
        logger.debug("endifs: " + endifs)
        val endif = if (endifs.size == 0) {
          (OP_ENDIF,t.size)
        } else if (endifs.size % 2 == 0) {
          //this means we need to take the first ENDIF, since we are nested inside of a parent OP_IF
          logger.debug("Even amount of OP_ENDIFs")
          val x = endifs.head
          (x._1,x._2 + 1)
        } else {
          //this means we need to take the last endif since we are not nested inside a parent OP_IF
          logger.debug("Odd amoutns of OP_ENDIFs")
          endifs.last
        }
        val nestedEndIfIndex = endif._2
        logger.debug("nestedEndIfIndex: " + nestedEndIfIndex)
        val nestedIf = t.take(nestedEndIfIndex)
        logger.debug("nestedIf: " + nestedIf)
        val opIfTree = loop(nestedIf,Leaf(h))
        logger.debug("opIfTree: " + opIfTree)

        val remaining = t.splitAt(nestedEndIfIndex)._2
        logger.debug("remaining: " + remaining)
        if (endifs.size % 2 == 0) {
          //this means we need to take the first ENDIF, since we are nested inside of a parent OP_IF
          logger.debug("Even amount of OP_ENDIFs")
          val subTree = insertSubTree(tree,opIfTree)
          logger.debug("subTree: " + subTree)
          //we need to pass in the opIfTree here because there are remaining elements nested inside the OP_IF tree
          val fullTree = loop(remaining,subTree)
          logger.debug("Done with even amounts OP_ENDIFs")
          logger.debug("fullTree: " + fullTree)
          fullTree
        } else {
          //this means we need to take the last endif since we are not nested inside a parent OP_IF
          logger.debug("odd amounts of OP_ENDIFs")

          val subTree = loop(remaining,opIfTree)
          logger.debug("subTree: " + subTree)
          //need to insert remainingTree in the OP_IF tree correctly, not sure if this is right
          //now insert into the parent tree
          val fullTree = tree match {
            case Empty => subTree
            case l: Leaf[ScriptToken] =>
              if (subTree == Empty) l
              else Node(l.v,subTree,Empty)
            case n: Node[ScriptToken] =>
              //require(n.l == Empty, "We can only insert an OP_IF on a left branch, it was not empty: " + n.l)
              Node(n.v,insertSubTree(n.l,subTree),n.r)
          }
          logger.debug("Done with odd amounts of OP_ENDIFS")
          logger.debug("fullTree: " + fullTree)
          fullTree
        }*/

        val (ifTree,remaining) = loop(t, Leaf(h))
        val fullTree = insertSubTree(tree,ifTree)
        logger.debug("fullTree: " + ifTree)
        (fullTree,remaining)
      case h :: t if h == OP_ELSE =>
        require(tree.value.isDefined && Seq(OP_IF, OP_NOTIF, OP_ELSE).contains(tree.value.get),
          "Parent of OP_ELSE has to be an OP_IF/NOTIF/ELSE, got: " + tree.value)
        require(tree.right.getOrElse(Empty) == Empty,"Right branch of tree should be Empty for an OP_ELSE, got: " + tree.right.get)
        val (subTree,remaining) = loop(t,Node(OP_ELSE,Empty,Empty))
        logger.debug("subTree else: " + subTree)
        val opElseTree = Node(tree.value.get, tree.left.getOrElse(Empty),subTree)
        logger.debug("opElseTree: " + opElseTree)
        (opElseTree,remaining)
      case h :: t => loop(t,insertSubTree(tree,Leaf(h)))
      case Nil =>
        logger.debug("Done parsing tree, got: "  + tree)
        (tree,Nil)
    }
  }

  /**
   * Inserts a sub tree into the parse tree of Script.
   * @param tree the parse tree of the control flow of the Script program
   * @param subTree the parse tree that needs to be inserted into the control flow of the program
   * @return the full parse tree combined
   */
  private def insertSubTree(tree: BinaryTree[ScriptToken],
                            subTree: BinaryTree[ScriptToken]): BinaryTree[ScriptToken] = tree match {
    case Empty => subTree
    case leaf: Leaf[ScriptToken] =>
      if (subTree == Empty) leaf
      else Node(leaf.v,subTree,Empty)
    case node : Node[ScriptToken] if (node.v == OP_IF || node.v == OP_ELSE) =>
      if (subTree.value.isDefined && Seq(OP_ELSE,OP_ENDIF).contains(subTree.value.get)) {
        Node(node.v,node.l,insertSubTree(node.r,subTree))
      } else if (node.r != Empty && Seq(OP_ELSE,OP_ENDIF).contains(node.r.value.get)) {
        Node(node.v,node.l,insertSubTree(node.r,subTree))
      } else {
        Node(node.v,insertSubTree(node.l,subTree),node.r)
      }
    case node: Node[ScriptToken] =>
      Node(node.v,insertSubTree(node.l,subTree), node.r)
  }

  /** Checks if an [[OP_IF]]/[[OP_NOTIF]] [[ScriptToken]] has a matching [[OP_ENDIF]] */
  def checkMatchingOpIfOpNotIfOpEndIf(script : List[ScriptToken]) : Boolean = {
    @tailrec
    def loop(script : List[ScriptToken], counter : Int) : Boolean = script match {
      case _ if (counter < 0) => false
      case OP_ENDIF :: t => loop(t,counter-1)
      case OP_IF :: t => loop(t, counter + 1)
      case OP_NOTIF :: t => loop(t, counter + 1)
      case (token : ScriptToken) :: t => loop(t, counter)
      case Nil => counter == 0
    }
    loop(script,0)
  }

  /** Returns the first index of an [[OP_ENDIF]]. */
  def findFirstOpEndIf(script : List[ScriptToken]) : Option[Int] = {
    val index = script.indexOf(OP_ENDIF)
    index match {
      case -1 => None
      case _ => Some(index)
    }
  }

  /** Finds the last [[OP_ENDIF]] in the given script. */
  def findLastOpEndIf(script : List[ScriptToken]) : Option[Int] = {
    val lastOpEndIf = findFirstOpEndIf(script.reverse)
    if (lastOpEndIf.isDefined) Some(script.size - lastOpEndIf.get - 1)
    else None
  }

  /** Returns the first index of an [[OP_ENDIF]]. */
  def findFirstOpElse(script : List[ScriptToken]) : Option[Int] = {
    val index = script.indexOf(OP_ELSE)
    index match {
      case -1 => None
      case _ => Some(index)
    }
  }

  /** Removes the first [[OP_ELSE]] expression encountered in the script. */
  def removeFirstOpElse(script : List[ScriptToken]) : List[ScriptToken] = {
    if (script.contains(OP_ELSE)) {
      val firstOpElseIndex = findFirstOpElse(script)
      val scriptWithoutFirstOpElse = script.zipWithIndex.filter(_._2 != firstOpElseIndex.get).map(_._1)
      val nextOpElseIndex = findFirstOpElse(scriptWithoutFirstOpElse)
      if(nextOpElseIndex.isDefined) {
        script.slice(0,firstOpElseIndex.get) ++ script.slice(nextOpElseIndex.get + 1, script.size)
      } else {
        val firstOpEndIfIndex = findFirstOpEndIf(script)
        script.slice(0,firstOpElseIndex.get) ++ script.slice(firstOpEndIfIndex.get, script.size)
      }
    } else script
  }

  /** Removes the first [[OP_ELSE]] in a [[BinaryTree]]. */
  def removeFirstOpElse(tree : BinaryTree[ScriptToken]) : BinaryTree[ScriptToken] = {
    tree match {
      case Empty => Empty
      case leaf : Leaf[ScriptToken] => leaf
      case node : Node[ScriptToken] =>
        logger.debug("Node: " + node)
        //need to traverse the tree to see if there is an OP_ENDIF on the left hand side
        val leftBranchContainsOpElse = node.l.contains[ScriptToken](OP_ELSE)()
        val leftBranchContainsOpIf = node.l.contains[ScriptToken](OP_IF)()
        logger.debug("leftBranchContainsOpElse " + leftBranchContainsOpElse)
        logger.debug("leftBranchContainsOpIf " + leftBranchContainsOpIf)
        if (leftBranchContainsOpElse && !leftBranchContainsOpIf) {
          //if the left branch contains an OP_ELSE but no OP_IF
          //then we need to delete the OP_ELSE in the left branch
          val subTree: Option[BinaryTree[ScriptToken]] = node.l.findFirstDFS[ScriptToken](OP_ELSE)()
          logger.debug("Sub tree: " + subTree)
          //need to remove the subtree for the OP_ELSE
          //need to insert the right branch of the subtree into the original place of the OP_ELSE
          if (subTree.isDefined) tree.replace(subTree.get, subTree.get.right.getOrElse(Empty))
          else tree
        } else if (node.r.value == Some(OP_ELSE) && node.r.left.isDefined && node.r.left.get.value == Some(OP_ENDIF)) {
          logger.debug("============================**********************************")
          Node(node.v,node.l,node.r.left.getOrElse(Empty))
        } else if (node.r.value == Some(OP_ELSE)) {
          Node(node.v,node.l,node.r.right.getOrElse(Empty))
        } else tree
    }
  }

  /** Removes the first [[OP_IF]] encountered in the script. */
  def removeFirstOpIf(script : List[ScriptToken]) : List[ScriptToken] = {
    val firstOpIfIndex = script.indexOf(OP_IF)
    val matchingOpEndIfIndex = findMatchingOpEndIf(script)

    val opIfExpression = script.slice(firstOpIfIndex,matchingOpEndIfIndex)
    val hasNestedIfExpression = opIfExpression.count(_ == OP_IF) > 1
    val (firstOpElseIndex,_) = findFirstIndexesOpElseOpEndIf(opIfExpression)

    if (firstOpElseIndex.isDefined && !hasNestedIfExpression) {
      script.slice(0,firstOpIfIndex) ++ script.slice(firstOpElseIndex.get,script.size)
    } else if (opIfExpression.contains(OP_IF)) {
      //if there is an OP_IF inside of the sub script then any OP_ELSES inside of there are bound to
      //that OP_IF
      script.slice(0,firstOpIfIndex) ++ script.slice(matchingOpEndIfIndex,script.size)
    }  else script.slice(0,firstOpIfIndex) ++ script.slice(matchingOpEndIfIndex,script.size)
  }

  /** Removes the first occurrence of [[OP_IF]] or [[OP_NOTIF]] in the [[BinaryTree]]. */
  def removeFirstOpIf(tree : BinaryTree[ScriptToken]) : BinaryTree[ScriptToken] = {
    require(tree.value.isDefined && (tree.value.get == OP_IF || tree.value.get == OP_NOTIF) , "Top of the tree must be OP_IF or OP_NOTIF to remove the OP_IF or OP_NOTIF")
    if (tree.right.isDefined && tree.right.get.value == Some(OP_ELSE)) tree.right.getOrElse(Empty)
    else tree.findFirstDFS[ScriptToken](OP_ENDIF)().getOrElse(Empty)
  }

  /** Finds the indexes of our [[OP_ELSE]] (if it exists) and our [[OP_ENDIF]]. */
  def findFirstIndexesOpElseOpEndIf(script : List[ScriptToken]) : (Option[Int],Option[Int]) = {
    val indexOpElse = findFirstOpElse(script)
    val indexOpEndIf = findFirstOpEndIf(script)
    (indexOpElse,indexOpEndIf)
  }

   /** Returns the index of the matching [[OP_ENDIF]] for the [[OP_IF]] statement. */
  def findMatchingOpEndIf(script : List[ScriptToken]) : Int = {
    val matchingOpEndIfIndex = findLastOpEndIf(script)
    require(matchingOpEndIfIndex.isDefined, "Every OP_IF must have a matching OP_ENDIF: " + script)
    matchingOpEndIfIndex.get
  }
}
