/**
 * Local cache helper for UI filter states and recent queries.
 * Note: Never store security-critical state here.
 */

const storageKey = (key) => `soc_dash_${key}`;

export const uiCache = {
  get: (key) => {
    try {
      const item = localStorage.getItem(storageKey(key));
      return item ? JSON.parse(item) : null;
    } catch {
      return null;
    }
  },
  set: (key, value) => {
    try {
      localStorage.setItem(storageKey(key), JSON.stringify(value));
    } catch (e) {
      console.warn("Storage full or disabled", e);
    }
  },
  remove: (key) => {
    localStorage.removeItem(storageKey(key));
  },
};
