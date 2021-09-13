const Big = require("big.js");
const { MerkleTree } = require("merkletreejs");
const fs = require("fs");
const crypto = require("crypto");
const { Command } = require('commander');
const readline = require('readline');
const { start, stop, job } = require("microjob");
const os = require("os")
const jobHandler = require("./jobHandler").jobHandler

const DELIMITER = "\t";
let NEW_LINE = "\r\n";
let THREADS = os.cpus().length - 1;

function SHA256(data) {
  return crypto.createHash('sha256').update(data).digest()
}

async function buildMerkle(content, headerRow, concatenate=false) {
  if (!content) {
    throw new Error("Please choose a file with valid balances!");
  }

  if (!headerRow.startsWith("#")) {
    throw new Error("Header row missing. Cannot proceed without it");
  }

  //start worker threads so we can make the cpu bound part faster
  await start({ maxWorkers: THREADS });

  const merkle_output = fs.createWriteStream('output_merkle_tree.txt')

  const columns = headerRow.split(",").map(item => item.trim());
  const tokens = columns.filter(column => !column.startsWith("#"));
  const total_balances = new Array(columns.length);

  let split_content = []
  const chunk_size = THREADS * 64
  for (let i=0, j= content.length - chunk_size; j > i; j -= chunk_size) {
    split_content.push(content.splice(j > 0 ? j : 0))
  }
  split_content.push(content)
  split_content.reverse()

  const res = await Promise.all(split_content.map(async part => {
    part.forEach(p => {
      const [uid, ...balances] = p.split(',')
      balances.forEach((balance, index) => {
        if (!total_balances[index]) total_balances[index] = Big(0)
        total_balances[index] = total_balances[index].add(balance);
      })
    })
    return job(jobHandler, { ctx: { part, columns, concatenate, tokens }})
  }));

  console.log("Leaf SHAing completed");

  //stop the worker threads since we don't need them anymore
  await stop();

  // build Merkle tree
  const tree = new MerkleTree(res.flat(2), SHA256);

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
    .option('-n, --newline <value>', 'Sets the type of line endings to expect from the input file. The output file will match this style. Possible options are crlf or lf.', 'crlf')
    .option('-t, --threads <value>', 'Number of worker threads to split the cpu intensive parts in. Defaults to all available CPUs -1. Be mindful that running lots of threads requires lots of memory so if you are getting heap out of memory exceptions try limiting the number of threads')
    .option('-i, --input <value>', 'Input filename', 'input.csv');

  program.parse();

  const { concatenate, input, newline, threads } = program.opts()

  if (newline === 'lf') {
    NEW_LINE = '\n'
  }

  if (threads) {
    const t = parseInt(threads);
    if (isNaN(t)) throw new Error(`Expected number of threads to be an integer. Found ${threads} instead`)
    THREADS = t;
  }

  const inputStream = fs.createReadStream(input);
  let content = []
  let headerRow = null;

  const rl = readline.createInterface({
    input: inputStream,
    crlfDelay: Infinity,
  });

  for await (let line of rl) {
    // Slight optimization. With large files removing the first line incurs a reindex of the whole array which is very
    // time consuming
    if (line.startsWith('#')) {
      headerRow = line;
      continue;
    }
    content.push(line);
  }
  console.info(content.length);

  inputStream.close();

  try {
    const [output, tokens, total_balances, tree] = await buildMerkle(content, headerRow, !!concatenate);
    fs.writeFileSync('output_total_balances.txt', `${tokens.map((token, i) => `${token}:${total_balances[i].toString()}`).join(NEW_LINE)}`)
    fs.writeFileSync('output_merkle_root.txt', tree.getRoot().toString("hex"))
    output.on("end", () => {
      output.close();
      process.exit(0);
    })
  } catch (e) {
    console.error(e);
    process.exit(1);
  }
}

main();
