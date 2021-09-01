const Big = require("big.js");
const { MerkleTree } = require("merkletreejs");
const SHA256 = require("crypto-js/sha256");
const fs = require("fs");
const { Command } = require('commander');
const readline = require('readline');

const LEAVES_HASH_LEN = 16;
const DELIMITER = "\t";
let NEW_LINE = "\r\n";

function buildMerkle(content, concatenate=false) {
  if (!content) {
    throw new Error("Please choose a file with valid balances!");
  }

  // read UID and balance from input file
  const total_balances = [];

  const merkle_output = fs.createWriteStream('output_merkle_tree.txt')

  let columns;
  let tokens;


  for (let i = 0; i < content.length; i++) {
    const row = content[i];
    const data = row.split(",").map(item => item.trim());

    // Check if we are in the header row, save the columns and skip
    if (row[0] === "#") {
      columns = data;
      tokens = columns.filter(column => !column.startsWith("#"));
      continue;
    }

    if (!columns) {
      throw new Error("Header row missing. Cannot proceed without it");
    }

    if (data.length !== columns.length) {
      throw new Error(`Please review the input file. Found ${data.length} columns at position ${i} instead of the expected ${columns.length}`);
    }

    const [uid, ...balances] = data;

    balances.forEach((balance, i) => {
      if (total_balances[i]) {
        total_balances[i] = total_balances[i].add(balance)
      } else {
        total_balances[i] = Big(balance)
      }
    });

    if (concatenate) {
      // Remove trailing zeroes using https://stackoverflow.com/a/53397618/1231428
      const sanitized_balances = balances.map(balance => balance.replace(/(\.[0-9]*[1-9])0+$|\.0*$/,"$1"));
      const string_to_hash = `${uid},${tokens.map((token, i) => [token, sanitized_balances[i]].join(":")).join(",")}`;
      content[i] = SHA256(string_to_hash)

    } else {
      const uid_hash = SHA256(uid);
      const concatenated_balances = balances.join('');
      const balance_hash = SHA256(concatenated_balances.toString());

      content[i] = SHA256(uid_hash.toString() + balance_hash.toString()).toString().substring(0, LEAVES_HASH_LEN); // underlying data to build Merkle tree
    }
  }

  // build Merkle tree
  const tree = new MerkleTree(content, SHA256);

  let treeLevels = tree.getLayers().length;
  let leavesFromTree = tree.getLeaves();


  merkle_output.write("Level" + DELIMITER + "Hash" + NEW_LINE);
  for (let i = 0; i < leavesFromTree.length; i++) {
    // write only the leaf nodes of the Merkle tree into verification file, all letters in lower case
    merkle_output.write(
      treeLevels +
      "," +
      i.toString() +
      DELIMITER +
      // shorten hashed value in leaves
      leavesFromTree[i].toString("hex") +
      NEW_LINE);
  }
  console.log("Merkle tree complete");
  return [merkle_output, tokens, total_balances, tree];
}

async function main() {
  const program = new Command();

  program
    .option('-c, --concatenate', 'If set, compute the leaves as SHA256(user_id,balance1:k,...,balancen:n). Otherwise the calculation is SHA256(SHA256(user_id)SHA256(balance1...balancen))')
    .option('-n, --newline <value>', 'Sets the type of line endings to expect from the input file. The output file will match this style. Possible options are crlf or lf. Defaults to crlf.', 'crlf')
    .option('-i, --input <value>', 'Input filename. Defaults to input.csv', 'input.csv');

  program.parse();

  const { concatenate, input, newline } = program.opts()

  if (newline === 'lf') {
    NEW_LINE = '\n'
  }

  const inputStream = fs.createReadStream(input);
  let content = []

  const rl = readline.createInterface({
    input: inputStream,
    crlfDelay: Infinity,
  });

  for await (let line of rl) {
    content.push(line);
  }
  console.info(content.length);
  inputStream.close();

  try {
    const [output, tokens, total_balances, tree] = buildMerkle(content, !!concatenate);
    fs.writeFileSync('output_total_balances.txt', `${tokens.map((token, i) => `${token}:${total_balances[i].toString()}`).join(NEW_LINE)}`)
    fs.writeFileSync('output_merkle_root.txt', tree.getRoot().toString("hex"))
    output.on("end", () => process.exit(0))
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
}

main();
