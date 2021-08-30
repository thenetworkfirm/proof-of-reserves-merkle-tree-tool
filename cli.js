const Big = require("big.js");
const { MerkleTree } = require("merkletreejs");
const SHA256 = require("crypto-js/sha256");
const fs = require("fs");
const { Command } = require('commander');

const LEAVES_HASH_LEN = 16;
const DELIMITER = "\t";
const NEW_LINE = "\r\n";

function buildMerkle(content, concatenate=false) {
  if (!content) {
    throw new Error("Please choose a file with valid balances!");
  }

  // read UID and balance from input file
  const balances_hash = [];
  const total_balances = []

  let columns;
  let tokens;

  const list = content.split(/\r?\n/);

  for (let i = 0; i < list.length; i++) {
    const row = list[i];
    const data = row.split(",").map(item => item.trim());

    // Check if we are in the header row, save the columns and skip
    if (row[0] === "#") {
      columns = data;
      tokens = columns.filter(column => !column.startsWith("#"))
      continue;
    }

    if (!columns) {
      throw new Error("Header row missing. Cannot proceed without it");
    }

    if (data.length !== columns.length) {
      throw new Error(`Please review the input file. Found ${data.length} columns at position ${i} instead of the expected ${columns.length}`);
    }

    const [uid, ...balances] = data;

    const sum_of_balances = balances.reduce((sum, balance, i) => {
      if (total_balances[i]) {
        total_balances[i] = total_balances[i].add(balance)
      } else {
        total_balances[i] = Big(balance)
      }
      return sum.add(balance)
    }, Big(0));


    const uid_hash = SHA256(uid);
    if (concatenate) {
      // Remove trailing zeroes using https://stackoverflow.com/a/53397618/1231428
      const sanitized_balances = balances.map(balance => balance.replace(/(\.[0-9]*[1-9])0+$|\.0*$/,"$1"))
      const string_to_hash = `${uid_hash},${tokens.map((token, i) => [token, sanitized_balances[i]].join(":")).join(",")}`
      balances_hash.push(string_to_hash)
    } else {
      const balance_hash = SHA256(sum_of_balances.toString());

      balances_hash.push(uid_hash.toString() + balance_hash.toString()); // underlying data to build Merkle tree
    }
  }
  // construct leaves and shorten hashed value in leaves
  const leaves = balances_hash.map((x) =>
    SHA256(x).toString().substring(0, LEAVES_HASH_LEN)
  );
  // build Merkle tree
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
      leavesFromTree[i].toString("hex") +
      NEW_LINE;
  }
  console.log("Merkle tree complete");
  return [output, tokens, total_balances, tree];
}

async function main() {
  const program = new Command();

  program
    .option('-c, --concatenate', 'If set, compute the leaves as SHA256(user_id,balance1:k,...,balancen:n)')
    .option('-i, --input', 'Input filename. Defaults to input.csv')

  program.parse()

  const { concatenate, input } = program.opts()

  let content = fs.readFileSync(input || 'input.csv', { encoding: 'utf-8' }).toString().trim()

  try {
    const [output, tokens, total_balances, tree] = buildMerkle(content, !!concatenate);
    fs.writeFileSync('output_merkle_tree.txt', output)
    fs.writeFileSync('output_total_balances.txt', `${tokens.map((token, i) => `${token}:${total_balances[i].toString()}`).join(NEW_LINE)}`)
    fs.writeFileSync('output_merkle_root.txt', tree.getRoot().toString("hex"))
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
}

main();
