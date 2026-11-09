// Toy custom cipher for vm tests: base64(reverse(plain)).
module.exports = {
  encrypt: (plain) => Buffer.from([...plain].reverse().join(''), 'utf8').toString('base64'),
  decrypt: (c) => [...Buffer.from(c, 'base64').toString('utf8')].reverse().join(''),
};
