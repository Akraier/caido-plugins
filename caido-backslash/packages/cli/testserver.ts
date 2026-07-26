/**
 * A deliberately vulnerable local target, for exercising the CLI end to end.
 *
 * Simulates an application that interpolates a query parameter into a quoted string in some
 * interpreter, so an odd number of trailing backslashes leaves the string unterminated and raises an
 * error, while an even number is a properly escaped literal and does not.
 *
 * It also echoes the parameter back, which is the realistic and difficult case: the echo alone makes
 * the two arms differ for a boring reason, so a correct detector must excise the reflection and
 * still see the error.
 *
 *   node packages/cli/testserver.ts [port]
 */

import { createServer } from "node:http";

const port = Number.parseInt(process.argv[2] ?? "8099", 10);
const MODE = process.env.MODE ?? "vulnerable";

/** Simulated round-trip latency, so concurrency can be measured against something realistic. */
const LATENCY_MS = Number.parseInt(process.env.LATENCY_MS ?? "0", 10);

const server = createServer((req, res) => {
  const chunks: Buffer[] = [];
  req.on("data", (c: Buffer) => chunks.push(c));
  req.on("end", () => handle(req, res, Buffer.concat(chunks).toString("utf8")));
});

/** Pull the tested parameter from the query, a urlencoded body, or a JSON body. */
function extractQ(req: { url?: string; headers: Record<string, unknown> }, body: string): string {
  const url = new URL(req.url ?? "/", `http://localhost:${port}`);
  const fromQuery = url.searchParams.get("q");
  if (fromQuery !== null && fromQuery !== "") return fromQuery;

  const contentType = String(req.headers["content-type"] ?? "").toLowerCase();
  if (contentType.includes("json")) {
    try {
      const parsed: unknown = JSON.parse(body);
      if (typeof parsed === "object" && parsed !== null && "q" in parsed) {
        return String((parsed as Record<string, unknown>).q ?? "");
      }
    } catch {
      // A deliberately invalid JSON payload is itself the test; fall through to the raw body.
      return body;
    }
    return "";
  }
  return new URLSearchParams(body).get("q") ?? "";
}

/** The single shared sink for `erb-stored`. Shared state is exactly what forces serialised pairs. */
let stored = "";

/**
 * A minimal ERB-like engine: unbalanced tags raise a parse error, a well-formed expression is
 * evaluated. Extracted so the redirect and stored modes render identically to the direct one -- a
 * second copy would drift and then the modes would not be testing the same engine.
 */
function renderErb(
  payload: string,
  echo: string,
  send: (status: number, body: string) => void,
): void {
  const opens = (payload.match(/<%/g) ?? []).length;
  const closes = (payload.match(/%>/g) ?? []).length;

  if (opens > closes) {
    send(
      500,
      `<html><body><div>SyntaxError: embedded document meets end of file ` +
        `(unterminated ERB tag)</div></body></html>`,
    );
    return;
  }

  const expression = /<%=\s*([^%]*?)\s*%>/.exec(payload);
  if (expression !== null) {
    const source = expression[1] ?? "";
    // Only arithmetic, and division by zero raises exactly as Ruby would.
    if (/^[0-9+\-*/() ]+$/.test(source)) {
      if (/\/\s*0+(?![1-9])/.test(source)) {
        send(500, "<html><body><div>ZeroDivisionError: divided by 0</div></body></html>");
        return;
      }
      let rendered: string;
      try {
        rendered = String(Function(`"use strict";return (${source})`)());
      } catch {
        send(500, "<html><body><div>SyntaxError in ERB expression</div></body></html>");
        return;
      }
      send(200, `<html><body><p>Hello ${rendered}</p><div>3 results</div></body></html>`);
      return;
    }
  }

  // Anything else, including a stray close tag, is inert literal text.
  send(200, `<html><body>${echo}<div>3 results</div></body></html>`);
}

/**
 * Render `${...}` interpolations, aborting at the first failing one.
 *
 * The abort is the important part: on error FreeMarker emits what it had produced so far, then the
 * error, and nothing else. Whatever followed the payload in the template -- the scanner's closing
 * canary included -- never reaches the response.
 */
function renderFreemarker(template: string): string {
  let out = "";
  let at = 0;
  for (;;) {
    const open = template.indexOf("${", at);
    if (open === -1) {
      out += template.slice(at);
      return out;
    }
    const close = template.indexOf("}", open + 2);
    if (close === -1) {
      // An unterminated interpolation is a parse error, and nothing renders at all.
      return "FreeMarker template error: unclosed interpolation, expecting &quot;}&quot;";
    }
    out += template.slice(at, open);
    const source = template.slice(open + 2, close);

    if (!/^[0-9+\-*/() .]+$/.test(source)) {
      // Not arithmetic: an undefined variable, which FreeMarker also treats as fatal.
      return (
        `${out}FreeMarker template error (DEBUG mode; use RETHROW in production!):\n` +
        `The following has evaluated to null or missing: ==> ${source}\n----\n` +
        `FTL stack trace ("~" means nesting-related):\n\t- Failed at: \${${source}}\n----\n` +
        `freemarker.core.InvalidReferenceException: [... Exception message was already printed ...]\n` +
        `\tat freemarker.core.InvalidReferenceException.getInstance(InvalidReferenceException.java:134)\n`
      );
    }
    if (/\/\s*0+(?![1-9.])/.test(source)) {
      // Status stays 200: the trace is rendered into the page, and rendering stops here.
      return (
        `${out}FreeMarker template error (DEBUG mode; use RETHROW in production!):\n` +
        `Arithmetic operation failed: / by zero\n----\n` +
        `FTL stack trace ("~" means nesting-related):\n\t- Failed at: \${${source}}\n----\n` +
        `Java stack trace (for programmers):\n----\n` +
        `freemarker.core._MiscTemplateException: [... Exception message was already printed ...]\n` +
        `\tat freemarker.core.ArithmeticExpression._eval(ArithmeticExpression.java:78)\n` +
        `\tat freemarker.core.Environment.process(Environment.java:310)\n` +
        `Caused by: java.lang.ArithmeticException: / by zero\n` +
        `\tat java.base/java.math.BigDecimal.divide(BigDecimal.java:1653)\n`
      );
    }
    let value: string;
    try {
      value = String(Function(`"use strict";return (${source})`)());
    } catch {
      return `${out}FreeMarker template error: could not evaluate \${${source}}`;
    }
    out += value;
    at = close + 1;
  }
}

function handle(req: any, res: any, body: string): void {
  const q = extractQ(req, body);
  const path = new URL(req.url ?? "/", `http://localhost:${port}`).pathname;

  // Everything after the opening canary is the payload under test.
  const marker = /bs[0-9a-z]{4}/.exec(q);
  const payload = marker === null ? "" : q.slice(marker.index + marker[0].length);
  const trailingBackslashes = /\\*$/.exec(payload)?.[0].length ?? 0;
  const unterminated = trailingBackslashes % 2 === 1;

  const echo = `<p>You searched for ${q}</p>`;
  const nonce = Math.random().toString(36).slice(2, 10);

  const send = (status: number, body: string): void => {
    const write = (): void => {
      // `Connection: close` on purpose. The CLI's Node provider reads until EOF rather than honouring
      // Content-Length, so a keep-alive response costs it the server's full idle timeout (~6s) per
      // request and the harness looks hung. Caido's own transport is unaffected; this keeps the
      // offline harness usable without pretending the provider is fixed.
      res.writeHead(status, {
        "Content-Type": "text/html; charset=utf-8",
        Connection: "close",
      });
      res.end(body);
    };
    if (LATENCY_MS > 0) setTimeout(write, LATENCY_MS);
    else write();
  };

  switch (MODE) {
    case "clean":
      send(200, `<html><body>${echo}<div>3 results</div><span>${nonce}</span></body></html>`);
      return;

    case "waf":
      if (unterminated) {
        send(403, "<html><body>Error code: 1020</body></html>");
        return;
      }
      send(200, `<html><body>${echo}<div>3 results</div></body></html>`);
      return;

    case "noisy":
      send(
        200,
        `<html><body>${echo}<div>csrf=${nonce}</div>` +
          `<span>${"x".repeat(Math.floor(Math.random() * 9))}</span></body></html>`,
      );
      return;

    case "tornado": {
      // A Tornado/Jinja-style engine that TOLERATES an unbalanced delimiter: an unclosed {{ is
      // emitted as literal text rather than raising. This is the case that defeats a probe which only
      // tests unbalanced delimiters, and it is why an evaluation probe is needed.
      const expression = /\{\{\s*([^}]*?)\s*\}\}/.exec(payload);
      if (expression !== null) {
        const source = expression[1] ?? "";
        if (/^[0-9+\-*/() ]+$/.test(source)) {
          if (/\/\s*0+(?![1-9])/.test(source)) {
            send(500, "<html><body><div>ZeroDivisionError: division by zero</div></body></html>");
            return;
          }
          let rendered: string;
          try {
            rendered = String(Function(`"use strict";return (${source})`)());
          } catch {
            // A literal Python would reject leading zeros here; mirror that.
            send(500, "<html><body><div>SyntaxError in template expression</div></body></html>");
            return;
          }
          send(200, `<html><body><p>Hello ${rendered}</p><div>3 results</div></body></html>`);
          return;
        }
      }
      // Anything else, including an unclosed tag, is inert literal text.
      send(200, `<html><body>${echo}<div>3 results</div></body></html>`);
      return;
    }

    case "erb": {
      renderErb(payload, echo, send);
      return;
    }

    /**
     * SSTI that renders on the REDIRECT TARGET, not on the injection endpoint.
     *
     * The injection endpoint always answers 302 with an identical body, so measuring it can never
     * find anything -- which is the point. Only following the Location and measuring /rendered
     * exposes the difference.
     */
    case "erb-redirect": {
      if (path === "/rendered") {
        const msg = new URL(req.url ?? "/", `http://localhost:${port}`).searchParams.get("msg") ?? "";
        const marked = /bs[0-9a-z]{4}/.exec(msg);
        const inner = marked === null ? msg : msg.slice(marked.index + marked[0].length);
        renderErb(inner, `<p>Message: ${msg}</p>`, send);
        return;
      }
      const write = (): void => {
        res.writeHead(302, {
          Location: `/rendered?msg=${encodeURIComponent(q)}`,
          "Content-Type": "text/html; charset=utf-8",
          Connection: "close",
        });
        // Byte-identical regardless of payload: the 3xx itself carries no signal at all.
        res.end("<html><body>Redirecting...</body></html>");
      };
      if (LATENCY_MS > 0) setTimeout(write, LATENCY_MS);
      else write();
      return;
    }

    /**
     * STORED SSTI: injected at one endpoint, rendered at another.
     *
     * The injection endpoint answers an identical 200 every time. The payload is only evaluated when
     * /profile is fetched, so this is unreachable without an observation URL. It is also the case
     * that mandates serialised pairs: `stored` is one shared slot, so two concurrent pairs would each
     * read the other's payload.
     */
    /**
     * The PortSwigger "template injection using documentation" shape, which the scanner missed.
     *
     * Three properties together are what defeated it, and all three matter:
     *
     *  1. POST saves the template and 302s to a GET that renders it -- so the payload is evaluated on a
     *     SHARED page, one round trip later. Concurrent pairs overwrite each other's template.
     *  2. The error is rendered INTO the page with status 200, so there is no status witness.
     *  3. FreeMarker aborts at the failing expression, so everything after the payload -- including the
     *     closing canary -- is never emitted. That marked every body feature unreliable and the whole
     *     measurement was discarded as inconclusive.
     */
    case "freemarker-stored": {
      if (path === "/product") {
        const rendered = renderFreemarker(stored);
        send(
          200,
          `<html><body><h3>More Than Just Birdsong</h3><label>Description:</label>\n${rendered}\n` +
            `<a href=/product/template>Edit template</a></body></html>`,
        );
        return;
      }
      const tpl = new URLSearchParams(body).get("template");
      if (tpl !== null) stored = tpl;
      const write = (): void => {
        res.writeHead(302, {
          Location: "/product?productId=1",
          "Content-Type": "text/html; charset=utf-8",
          Connection: "close",
        });
        // Identical every time: measuring this response can never find anything.
        res.end("");
      };
      if (LATENCY_MS > 0) setTimeout(write, LATENCY_MS);
      else write();
      return;
    }

    case "erb-stored": {
      if (path === "/profile") {
        const marked = /bs[0-9a-z]{4}/.exec(stored);
        const inner = marked === null ? stored : stored.slice(marked.index + marked[0].length);
        renderErb(inner, `<p>Bio: ${stored}</p>`, send);
        return;
      }
      stored = q;
      send(200, "<html><body><div>Saved.</div></body></html>");
      return;
    }

    case "vulnerable":
    default:
      if (unterminated) {
        send(
          500,
          `<html><body>${echo}<div>You have an error in your SQL syntax; ` +
            `unclosed quotation mark after the character string</div></body></html>`,
        );
        return;
      }
      send(200, `<html><body>${echo}<div>3 results</div><span>${nonce}</span></body></html>`);
      return;
  }
}

server.listen(port, "127.0.0.1", () => {
  console.log(`test target listening on http://127.0.0.1:${port} (MODE=${MODE})`);
});
