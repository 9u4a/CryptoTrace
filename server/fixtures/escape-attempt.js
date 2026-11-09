// Must fail inside the sandbox: no require/process/fetch in scope.
module.exports = {
  encrypt: () => String(typeof require) + typeof process + typeof fetch,
  decrypt: () => { while (true) {} },
};
