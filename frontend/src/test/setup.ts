// Vitest setup, applied to every test file.
//
// jsdom implements no CSS media query engine, so window.matchMedia is simply
// absent — and ReadPage calls it during render to decide whether touch swipe
// gestures apply. Without this stub any component test of that page throws
// before rendering a single element.
//
// Guarded on `window` because some suites deliberately run in the node
// environment (pgpClient.test.ts, where openpgp's Uint8Array handling breaks
// under jsdom), and this file loads for those too.
if (typeof window !== "undefined" && typeof window.matchMedia !== "function") {
  window.matchMedia = (query: string): MediaQueryList =>
    ({
      // Reporting no match means tests exercise the pointer-fine (desktop)
      // path, which is the one whose click handlers they drive.
      matches: false,
      media: query,
      onchange: null,
      addListener: () => {},
      removeListener: () => {},
      addEventListener: () => {},
      removeEventListener: () => {},
      dispatchEvent: () => false
    }) as MediaQueryList;
}

// jsdom parses <dialog> but implements none of its behaviour, so showModal and
// close are missing. The reader opens in a dialog (useDialogOpen), so without
// these no message can be opened in a test. Toggling the `open` property is
// what the real methods do that this codebase depends on — it is what
// useDialogOpen reads back to avoid double-opening.
if (typeof HTMLDialogElement !== "undefined" && typeof HTMLDialogElement.prototype.showModal !== "function") {
  HTMLDialogElement.prototype.showModal = function showModal(this: HTMLDialogElement) {
    this.open = true;
  };
  HTMLDialogElement.prototype.close = function close(this: HTMLDialogElement) {
    this.open = false;
    this.dispatchEvent(new Event("close"));
  };
}

// Node 26 (what CI pins, matching the Dockerfile) ships its own `localStorage`
// global, and without --localstorage-file it evaluates to `undefined` — which
// shadows the jsdom implementation. Node 24, which is what most local installs
// still have, has no such global and jsdom's wins. That difference is why
// draftAutosave.test.ts passed on every developer machine and failed all 14
// cases in CI with "Cannot read properties of undefined (reading 'clear')".
//
// Installing a real, spec-shaped implementation here makes the tests depend on
// this file rather than on which Node the runner happens to have. Paired with
// .nvmrc and package.json "engines", which stop the local/CI drift at source.
if (typeof window !== "undefined" && !window.localStorage) {
  const backing = new Map<string, string>();
  Object.defineProperty(window, "localStorage", {
    configurable: true,
    value: {
      getItem: (key: string): string | null => backing.get(String(key)) ?? null,
      setItem: (key: string, value: string): void => {
        backing.set(String(key), String(value));
      },
      removeItem: (key: string): void => {
        backing.delete(String(key));
      },
      clear: (): void => {
        backing.clear();
      },
      key: (index: number): string | null => [...backing.keys()][index] ?? null,
      get length(): number {
        return backing.size;
      }
    } satisfies Storage
  });
}
