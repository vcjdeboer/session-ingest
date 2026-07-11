/**
 * @vcjdeboer/session-ingest — render_html.ts
 *
 * `render_html`: the VISUAL companion to the `capture-report`. It runs the exact
 * same report (`capture_report.ts` → markdown + structured JSON over the sealed
 * facets), converts the markdown to a styled, self-contained HTML page, and
 * embeds the captured PNG figures inline (read from the sealed corpus blobs by
 * checksum). One source (the report), two renderings (text + visual). Reads only
 * sealed swamp data from the repo's data store; writes a single .html file.
 *
 * @module
 */
import { z } from "npm:zod@4";
import { type CaptureReportContext, report } from "./capture_report.ts";

/* ----------------------------- disk-backed reader ----------------------------- */
/** A dataRepository over the on-disk swamp data store (the report reads via this). */
function diskRepo(base: string): CaptureReportContext["dataRepository"] {
  const versions = (name: string): number[] => {
    try {
      return [...Deno.readDirSync(`${base}/${name}`)]
        .filter((e) => e.isDirectory && /^\d+$/.test(e.name))
        .map((e) => Number(e.name)).sort((a, b) => a - b);
    } catch {
      return [];
    }
  };
  const specOf = (name: string, v: number): string | undefined => {
    try {
      return /specName:\s*(\S+)/.exec(
        Deno.readTextFileSync(`${base}/${name}/${v}/metadata.yaml`),
      )?.[1];
    } catch {
      return undefined;
    }
  };
  return {
    async getContent(_t, _m, dataName, version) {
      const vs = versions(dataName);
      const v = version ?? (vs.length ? vs[vs.length - 1] : 1);
      try {
        return await Deno.readFile(`${base}/${dataName}/${v}/raw`);
      } catch {
        return null;
      }
    },
    findAllForModel() {
      const out: Array<
        { name: string; version: number; tags?: Record<string, string> }
      > = [];
      for (const e of Deno.readDirSync(base)) {
        if (!e.isDirectory) continue;
        for (const v of versions(e.name)) {
          const s = specOf(e.name, v);
          out.push({
            name: e.name,
            version: v,
            tags: s ? { specName: s } : {},
          });
        }
      }
      return Promise.resolve(out);
    },
  };
}

/** Locate the session-ingest data dir under the repo (`.swamp/data/<type>/<modelId>`). */
function resolveDataDir(): { base: string; modelId: string } {
  const repoDir = Deno.env.get("SWAMP_REPO_DIR") || Deno.cwd();
  const typeDir = `${repoDir}/.swamp/data/@vcjdeboer/session-ingest`;
  const dirs = [...Deno.readDirSync(typeDir)]
    .filter((e) => e.isDirectory && e.name.includes("-"));
  // prefer a model dir that actually holds captured sessions (a bundle-manifest resource)
  const withData = dirs.find((d) => {
    try {
      return [...Deno.readDirSync(`${typeDir}/${d.name}`)].some((x) =>
        x.isDirectory && x.name.startsWith("proj_")
      );
    } catch {
      return false;
    }
  }) ?? dirs[0];
  if (!withData) throw new Error(`no session-ingest data under ${typeDir}`);
  return { base: `${typeDir}/${withData.name}`, modelId: withData.name };
}

/* ------------------------------ markdown → HTML ------------------------------ */
function esc(t: string): string {
  return t.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
function inlineMd(t: string): string {
  let s = esc(t);
  s = s.replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>");
  s = s.replace(/`([^`]+)`/g, "<code>$1</code>");
  s = s.replace(/(^|[^\w])_([^_]+)_(?!\w)/g, "$1<em>$2</em>");
  s = s.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
  return s;
}
/** Convert the report markdown to HTML, embedding figures via `figureUri(sha12)`. */
export function mdToHtml(
  md: string,
  figureUri: (sha12: string) => string | null,
): string {
  const lines = md.split("\n");
  const out: string[] = [];
  const stack: string[] = [];
  const close = () => {
    while (stack.length) out.push(`</${stack.pop()}>`);
  };
  for (let i = 0; i < lines.length; i++) {
    const ln = lines[i];
    const fig = /^- `([0-9a-f]{6,})` — (\d+) KB \(PNG\)/.exec(ln.trim());
    if (fig) {
      close();
      const uri = figureUri(fig[1]);
      if (uri) {
        out.push(
          `<figure class="fig"><img alt="${fig[1]}" src="${uri}"><figcaption>${
            fig[1]
          } · ${fig[2]} KB</figcaption></figure>`,
        );
      } else out.push(`<p class="miss">figure ${fig[1]} (${fig[2]} KB)</p>`);
      continue;
    }
    const h = /^(#{1,3})\s+(.*)$/.exec(ln);
    if (h) {
      close();
      out.push(`<h${h[1].length}>${inlineMd(h[2])}</h${h[1].length}>`);
      continue;
    }
    if (
      ln.trim().startsWith("|") && i + 1 < lines.length &&
      /^\s*\|[-\s|]+\|\s*$/.test(lines[i + 1])
    ) {
      close();
      const hdr = ln.trim().replace(/^\||\|$/g, "").split("|").map((c) =>
        c.trim()
      );
      out.push(
        `<div class="tw"><table><thead><tr>${
          hdr.map((c) => `<th>${inlineMd(c)}</th>`).join("")
        }</tr></thead><tbody>`,
      );
      i += 2;
      while (i < lines.length && lines[i].trim().startsWith("|")) {
        const cs = lines[i].trim().replace(/^\||\|$/g, "").split("|").map((c) =>
          c.trim()
        );
        out.push(
          `<tr>${cs.map((c) => `<td>${inlineMd(c)}</td>`).join("")}</tr>`,
        );
        i++;
      }
      i--;
      out.push("</tbody></table></div>");
      continue;
    }
    if (ln.trim().startsWith(">")) {
      close();
      const buf: string[] = [];
      while (i < lines.length && lines[i].trim().startsWith(">")) {
        buf.push(lines[i].trim().slice(1).trim());
        i++;
      }
      i--;
      out.push(
        `<blockquote>${inlineMd(buf.filter(Boolean).join(" "))}</blockquote>`,
      );
      continue;
    }
    const ol = /^(\d+)\.\s+(.*)$/.exec(ln);
    if (ol) {
      if (stack[stack.length - 1] !== "ol") {
        close();
        out.push("<ol>");
        stack.push("ol");
      }
      out.push(`<li>${inlineMd(ol[2])}</li>`);
      continue;
    }
    const ul = /^[-*]\s+(.*)$/.exec(ln);
    if (ul) {
      if (stack[stack.length - 1] !== "ul") {
        close();
        out.push("<ul>");
        stack.push("ul");
      }
      out.push(`<li>${inlineMd(ul[1])}</li>`);
      continue;
    }
    if (!ln.trim()) {
      close();
      continue;
    }
    close();
    out.push(`<p>${inlineMd(ln)}</p>`);
  }
  close();
  return out.join("\n");
}

const CSS =
  `:root{--ground:#FBFCFD;--panel:#fff;--ink:#15191E;--muted:#5C6672;--line:#E4E8EC;--accent:#0F766E;--faint:#F3F5F7}` +
  `*{box-sizing:border-box}body{margin:0;background:var(--ground);color:var(--ink);font-family:system-ui,-apple-system,sans-serif;line-height:1.6}` +
  `.wrap{max-width:820px;margin:0 auto;padding:44px 24px 120px}` +
  `h1{font-family:"Iowan Old Style",Georgia,serif;font-size:34px;margin:0 0 6px;text-wrap:balance;font-weight:600}` +
  `h2{font-size:13px;text-transform:uppercase;letter-spacing:.11em;color:var(--accent);margin:44px 0 4px;font-weight:700;border-top:1px solid var(--line);padding-top:26px}` +
  `h3{font-size:16px;margin:20px 0 6px}p{margin:10px 0}strong{font-weight:640}` +
  `code{font-family:ui-monospace,Menlo,monospace;font-size:.86em;background:var(--faint);border:1px solid var(--line);border-radius:5px;padding:1px 6px}` +
  `a{color:var(--accent)}blockquote{margin:12px 0;padding:12px 18px;background:var(--panel);border-left:3px solid var(--accent);border-radius:0 8px 8px 0;font-size:16px}` +
  `h2+blockquote{font-size:19px;font-family:"Iowan Old Style",Georgia,serif}ol,ul{margin:10px 0;padding-left:22px}li{margin:7px 0}` +
  `.tw{overflow-x:auto;margin:14px 0}table{border-collapse:collapse;font-size:13px;width:100%}` +
  `th,td{text-align:left;padding:7px 12px;border-bottom:1px solid var(--line)}th{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted)}` +
  `td code{background:none;border:0;padding:0;color:var(--muted)}` +
  `.fig{margin:16px 0;border:1px solid var(--line);border-radius:12px;overflow:hidden;background:var(--panel)}` +
  `.fig img{display:block;width:100%;max-height:520px;object-fit:contain;background:#fff}` +
  `.fig figcaption{padding:9px 14px;font-size:12px;color:var(--muted);border-top:1px solid var(--line);font-family:ui-monospace,monospace}` +
  `footer{margin-top:50px;padding-top:20px;border-top:1px solid var(--line);color:var(--muted);font-size:13px}`;

const b64 = (bytes: Uint8Array): string => {
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
};

export const VisualSchema = z.object({
  session: z.string().nullable(),
  outPath: z.string(),
  bytes: z.number(),
  figuresEmbedded: z.number(),
});

export const RenderHtmlArgsSchema = z.object({
  project: z.string().min(1),
  /** Output .html path (default: <proj_id>_capture_report.html in the cwd). */
  out: z.string().default(""),
  csRoot: z.string().default(""),
  orgId: z.string().default(""),
});

interface RenderSink {
  writeResource: (
    s: string,
    i: string,
    d: unknown,
  ) => Promise<{ version: number }>;
  logger: { info: (m: string, p?: Record<string, unknown>) => void };
}

/** Render the capture-report to a styled, figure-embedded HTML file. */
export async function renderHtml(
  args: z.infer<typeof RenderHtmlArgsSchema>,
  sink: RenderSink,
): Promise<{ dataHandles: unknown[] }> {
  const { base, modelId } = resolveDataDir();
  const repo = diskRepo(base);
  const res = await report.execute({
    modelType: "@vcjdeboer/session-ingest",
    modelId,
    dataRepository: repo,
    methodArgs: { project: args.project },
  });
  const json = res.json as Record<string, unknown>;
  const figs = (json.figures as Array<{ sha: string; kb: number }>) ?? [];
  // sha12 → data-uri (read the full-checksum blob, PNG bytes → base64)
  const uriBy: Record<string, string> = {};
  for (const f of figs) {
    const bytes = await repo.getContent(
      "@vcjdeboer/session-ingest",
      modelId,
      f.sha,
      1,
    );
    if (bytes) {
      uriBy[f.sha.slice(0, 12)] = `data:image/png;base64,${b64(bytes)}`;
    }
  }
  const body = mdToHtml(res.markdown, (s12) => uriBy[s12] ?? null);
  const titleM = /<h1>(.*?)<\/h1>/.exec(body);
  const title = titleM ? titleM[1].replace(/<[^>]+>/g, "") : "Capture report";
  const doc = `<title>${esc(title)}</title>\n<style>${CSS}</style>\n` +
    `<div class="wrap">\n${body}\n<footer>Rendered by <code>@vcjdeboer/session-ingest render_html</code> ` +
    `from the sealed capture — figures embedded from the corpus. Nothing from the live app.</footer>\n</div>`;

  const outPath = args.out ||
    `${(json.resource as string) ?? "session"}_capture_report.html`;
  await Deno.writeTextFile(outPath, doc);
  const handle = await sink.writeResource(
    "visual",
    String(json.resource ?? args.project),
    {
      session: json.session ?? null,
      outPath,
      bytes: doc.length,
      figuresEmbedded: Object.keys(uriBy).length,
    },
  );
  sink.logger.info("render_html wrote visual report", {
    outPath,
    kb: Math.round(doc.length / 1024),
    figures: Object.keys(uriBy).length,
  });
  return { dataHandles: [handle] };
}
