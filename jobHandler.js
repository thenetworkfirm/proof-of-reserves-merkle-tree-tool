const jobHandler = () => {
  function SHA256(data) {
    return crypto.createHash('sha256').update(data).digest()
  }

  const crypto = require('crypto');

  for (let i = 0; i < part.length; i++) {
    const row = part[i];
    const d = row.split(",")
      .map(item => item.trim());

    if (d.length !== columns.length) {
      throw new Error(`Please review the input file. Found ${d.length} columns instead of the expected ${columns.length}`);
    }

    const [uid, ...balances] = d;

    if (concatenate) {
      // Remove trailing zeroes using https://stackoverflow.com/a/53397618/1231428
      const sanitized_balances = balances.map(balance => balance.replace(/(\.[0-9]*[1-9])0+$|\.0*$/,"$1"));
      const string_to_hash = `${uid},${tokens.map((token, i) => [token, sanitized_balances[i]].join(":")).join(",")}`;
      part[i] = SHA256(string_to_hash).toString('hex').substring(0, 16)

    } else {
      const uid_hash = SHA256(uid);
      const concatenated_balances = balances.join('');
      const balance_hash = SHA256(concatenated_balances);

      part[i] = SHA256(uid_hash.toString('hex') + balance_hash.toString('hex')).toString('hex').substring(0, 16); // underlying d to build Merkle tree
    }
  }

  return [part]
}

module.exports = { jobHandler }
