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

const server = createServer((req, res) => {
  const url = new URL(req.url ?? "/", `http://localhost:${port}`);
  const q = url.searchParams.get("q") ?? "";

  // Everything after the opening canary is the payload under test.
  const marker = /bs[0-9a-z]{4}/.exec(q);
  const payload = marker === null ? "" : q.slice(marker.index + marker[0].length);
  const trailingBackslashes = /\\*$/.exec(payload)?.[0].length ?? 0;
  const unterminated = trailingBackslashes % 2 === 1;

  const echo = `<p>You searched for ${q}</p>`;
  const nonce = Math.random().toString(36).slice(2, 10);

  const send = (status: number, body: string): void => {
    res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
    res.end(body);
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
});

server.listen(port, "127.0.0.1", () => {
  console.log(`test target listening on http://127.0.0.1:${port} (MODE=${MODE})`);
});
