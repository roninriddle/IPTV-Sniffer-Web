/* Serialize writes so an older slow save cannot overwrite newer input. */
(function (root) {
  function createSettingsQueue(send) {
    let tail = Promise.resolve();
    return function save(payload) {
      const snapshot = JSON.parse(JSON.stringify(payload));
      const next = tail.then(() => send(snapshot));
      tail = next.catch(() => undefined);
      return next;
    };
  }
  if (typeof module !== 'undefined') module.exports = {createSettingsQueue};
  else root.createSettingsQueue = createSettingsQueue;
})(typeof window !== 'undefined' ? window : globalThis);
