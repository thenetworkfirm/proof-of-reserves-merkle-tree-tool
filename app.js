const Big = require("big.js");
const { MerkleTree } = require("merkletreejs");
const SHA256 = require("crypto-js/sha256");

const LEAVES_HASH_LEN = 16;
const DELIMITER = "\t";
const NEW_LINE = "\r\n";

let rawFile, merkleFile;
/**
 * interaction between HTML and js code
 */
$(function () {
  let TXT, VerifyTXT;
  // create Merkle tree with user input of a list of (id, balances)
  $(".getMerkleTxtBox .btn").click(function () {
    createMerkle(TXT, rawFile);
  });

  // upload leave nodes of the Merkle tree
  $(".upLoadTxt").change(function (event) {
    var files = event.target.files;
    rawFile = files[0].name;
    var input = event.target;
    var reader = new FileReader();
    reader.onload = function () {
      if (reader.result) {
        // retrieve file content
        TXT = reader.result;
      }
    };
    reader.readAsText(input.files[0]);
  });

  // verify user input of (userId, userBalance(s)) within the Merkle tree that constructed by the given leaf nodes
  $(".verifyBox .btn").click(() => {
    verifyMerkle(VerifyTXT, {
      uid: $(".upLoadTxtUid").val(),
      balance1: $(".balance1").val(),
      balance2: $(".balance2").val(),
      balance3: $(".balance3").val(),
      balance4: $(".balance4").val(),
      rootHash: $(".upLoadTxtRootHash").val(),
      url: merkleFile,
    });
  });

  // upload leaf nodes of the Merkle tree for verification
  $(".upLoadMerkle").change(function (event) {
    var files = event.target.files;
    merkleFile = files[0].name;
    var input = event.target;
    var reader = new FileReader();
    reader.onload = function () {
      if (reader.result) {
        // retrieve file content
        VerifyTXT = reader.result;
      }
    };
    reader.readAsText(input.files[0]);
  });
});

/**
 * convert given string into hex format
 * @param value
 * @returns {string}
 */
function bufferToString(value) {
  return value.toString("hex");
}

/**
 * build Merkle tree using input data, and save the data of leaf nodes in resTxt
 * @method merkle
 * @param {String} content of input file
 * @param {String} fileName name of input file
 * @return {JSON} root rowsNum totalBalance
 */
function createMerkle(content, fileName) {
  if (!fileName || !content) {
    alert("Please choose a file with valid balances!");
    return;
  }

  // process input file
  let list = content.replace(/\r/g, "").split(/\n/); // read UID and balance from input file
  let balances_hash = [];
  let totalBalance1 = Big("0.0");
  let totalBalance2 = Big("0.0");
  let totalBalance3 = Big("0.0");
  let totalBalance4 = Big("0.0");

  for (var i = 0; i < list.length; i++) {
    var row = list[i];
    if (row[0] == "#") {
      continue;
    }
    var data = row.split(",");
    if (data.length !== 5) {
      continue;
    }

    const [uid, balance1, balance2, balance3, balance4] = data;
    totalBalance1 = totalBalance1.add(balance1);
    totalBalance2 = totalBalance2.add(balance2);
    totalBalance3 = totalBalance3.add(balance3);
    totalBalance4 = totalBalance4.add(balance4);

    const balance = balance1 + balance2 + balance3 + balance4;

    //concatenate id and balances to form transaction data
    var uid_hash = SHA256(uid);
    var balance_hash = SHA256(balance);

    balances_hash.push(uid_hash + balance_hash); // underlying data to build Merkle tree
  }
  // construct leaves and shorten hashed value in leaves
  const leaves = balances_hash.map((x) =>
    SHA256(x).toString().substring(0, LEAVES_HASH_LEN)
  );
  // build Merlke tree
  const tree = new MerkleTree(leaves, SHA256);

  let treeLevels = tree.getLayers().length;
  let leavesFromTree = tree.getLeaves();
  let output = "Level" + DELIMITER + "Hash" + NEW_LINE;
  for (let i = 0; i < leavesFromTree.length; i++) {
    // write only the leaf nodes of the Merkle tree into verification file, all letters in lower case
    output +=
      treeLevels +
      "," +
      i.toString() +
      DELIMITER +
      // shorten hashed value in leaves
      bufferToString(leavesFromTree[i]) +
      NEW_LINE;
  }
  console.log("Merkle tree complete");

  // save the Merkle tree data as verify file
  let resFileName = fileName.split(".")[0];
  resFileName += "_merkletree.txt";
  let file = new File([output], resFileName, {
    type: "text/plain;charset=utf-8",
  });
  saveAs(file);

  $(".rootHash").html(bufferToString(tree.getRoot()));
  $(".rowsNum").html(leavesFromTree.length);
  $(".totalBalance1").html(totalBalance1.toFixed());
  $(".totalBalance2").html(totalBalance2.toFixed());
  $(".totalBalance3").html(totalBalance3.toFixed());
  $(".totalBalance4").html(totalBalance4.toFixed());
}

/**
 * validate user balance
 *
 * @method merkle
 * @param {String} VerifyTXT verification file with all hashed value
 * @param {String} params  containing a pair of (uid and balance) to be verified
 * @return {JSON} checkRes (validation result, boolean)  nodesLocation（location of user node） {"checkRes":true,"nodesLocation":"4,0"}
 */

function verifyMerkle(VerifyTXT, params) {
  if (!VerifyTXT) {
    alert("Please choose a file with valid content!");
    return;
  }

  if (
    !params.uid ||
    !params.balance1 ||
    !params.balance2 ||
    !params.balance3 ||
    !params.balance4
  ) {
    alert("Please input id and balances for verification");
    return;
  }

  // compute the hashed value with given uid and balance
  let uid = params.uid;
  const balance =
    params.balance1 + params.balance2 + params.balance3 + params.balance4;

  var uid_hash = SHA256(uid);
  var balance_hash = SHA256(balance);

  let leafStr = SHA256(uid_hash + balance_hash)
    .toString()
    .substring(0, LEAVES_HASH_LEN);

  // process input value
  var list = VerifyTXT.split(NEW_LINE);
  list.splice(0, 1); // remove header row
  let leaves = [];
  let nodesLocation = undefined;
  for (var i = 0; i < list.length; i++) {
    var l = list[i];
    if (l[0] == "#") continue;
    var c = l.split("\t");
    if (c.length != 2) continue;
    var hash = c[1].trim();
    leaves.push(hash);
    if (leafStr === hash) {
      nodesLocation = i;
    }
  }
  if (nodesLocation == undefined) {
    alert("Could not find your information in the Merkle Tree.");
    return;
  }

  // start Merkle tree verification
  let options = {
    hashLeaves: false,
  };

  // construct Merkle tree without hashing the leaves
  const tree = new MerkleTree(leaves, SHA256, options);
  const root = bufferToString(tree.getRoot());
  $(".computedRootHash").html(root);

  const proof = tree.getProof(leafStr);

  let depth = tree.getLayers().length;
  let resObj = {
    checkRes: tree.verify(proof, leafStr, root),
    level: depth.toString(),
    position: nodesLocation.toString(),
  };
  if (resObj.checkRes) {
    $(".result").html(
      "Successful! Found your input data in the Merkle Tree at Level: " +
        resObj.level +
        ", Position: " +
        resObj.position
    );
  } else {
    $(".result").html("Could not find your input data in the Merkle Tree.");
  }
}
