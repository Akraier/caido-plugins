/**
 * Minimal ambient declarations for host globals the engine relies on.
 *
 * The tsconfig deliberately sets `lib: ["ES2023"]` and `types: []` so that nothing can compile
 * against a browser or Node API that Caido's QuickJS backend does not actually provide. That
 * ceiling is a feature: it turns "works on my machine" into a compile error.
 *
 * AbortController and AbortSignal are documented as available globals in the Caido plugin
 * runtime, and are also present in Node for the fixture harness, so only these are declared.
 * Only the members actually used are listed; anything more would be an unverified claim about
 * the runtime.
 */

interface AbortSignal {
  readonly aborted: boolean;
  addEventListener(type: "abort", listener: () => void): void;
  removeEventListener(type: "abort", listener: () => void): void;
}

interface AbortController {
  readonly signal: AbortSignal;
  abort(): void;
}

declare const AbortController: {
  prototype: AbortController;
  new (): AbortController;
};
