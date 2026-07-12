/**
 * @vcjdeboer/session-ingest — notifications.ts
 *
 * `capture_notifications`: freeze the PARENT<->CHILD delegation messages of a
 * QUIESCENT Claude Science session. When a session uses `host.delegate`, the
 * coordinator and its sub-agents exchange `notifications` (task payloads,
 * results) that the transcript's per-frame turns don't carry — the coordination
 * layer between frames. This seals them into a SENSITIVE `notifications`
 * resource so the delegation flow is reconstructable from sealed data alone.
 * `payload` is coordination/analysis prose, never a credential.
 *
 * @module
 */
import { z } from "npm:zod@4";
import {
  assertQuiescent,
  cloneDb,
  preflightSqlite,
  PROJ_ID_RE,
  QUERIES,
  readClone,
  resolveOrgDir,
} from "./db.ts";

export const NotificationSchema = z.object({
  senderFrameId: z.string().nullable(),
  recipientFrameId: z.string().nullable(),
  rootFrameId: z.string().nullable(),
  type: z.string().default(""),
  payload: z.string().default(""), // verbatim JSON payload (coordination prose)
  read: z.boolean(),
  createdAt: z.number().nullable(),
});
export type Notification = z.infer<typeof NotificationSchema>;

export const NotificationsSchema = z.object({
  sensitive: z.literal(true),
  session: z.string(),
  total: z.number(),
  byType: z.record(z.string(), z.number()),
  notifications: z.array(NotificationSchema).default([]),
  origin: z.object({
    tool: z.literal("claude-science"),
    org: z.string(),
    project: z.object({ id: z.string(), name: z.string().nullable() }),
  }),
});
export type Notifications = z.infer<typeof NotificationsSchema>;

interface RawNotification {
  sender_frame_id?: unknown;
  recipient_frame_id?: unknown;
  root_frame_id?: unknown;
  notification_type?: unknown;
  payload?: unknown;
  read_at?: unknown;
  created_at?: unknown;
}

const nstr = (v: unknown): string | null => (v == null ? null : String(v));
const nnum = (v: unknown): number | null =>
  typeof v === "number" ? v : (v == null ? null : Number(v) || null);

/** Shape raw notifications rows into the sealed set + a per-type tally. Pure. */
export function buildNotifications(
  rows: RawNotification[],
): { notifications: Notification[]; byType: Record<string, number> } {
  const notifications: Notification[] = [];
  const byType: Record<string, number> = {};
  for (const r of rows) {
    const type = String(r.notification_type ?? "");
    byType[type] = (byType[type] ?? 0) + 1;
    notifications.push({
      senderFrameId: nstr(r.sender_frame_id),
      recipientFrameId: nstr(r.recipient_frame_id),
      rootFrameId: nstr(r.root_frame_id),
      type,
      payload: r.payload == null
        ? ""
        : (typeof r.payload === "string"
          ? r.payload
          : JSON.stringify(r.payload)),
      read: r.read_at != null,
      createdAt: nnum(r.created_at),
    });
  }
  return { notifications, byType };
}

interface NotificationsSink {
  writeResource: (
    s: string,
    i: string,
    d: unknown,
  ) => Promise<{ version: number }>;
  logger: { info: (m: string, p?: Record<string, unknown>) => void };
}

/** Capture the project's inter-agent notifications into a SENSITIVE resource. */
export async function captureNotifications(
  csRoot: string,
  projectArg: string,
  orgId: string | undefined,
  sink: NotificationsSink,
): Promise<{ dataHandles: unknown[] }> {
  const pre = await preflightSqlite();
  if (!pre.ok) throw new Error(pre.error);
  const { orgDir, org } = resolveOrgDir(csRoot, orgId);
  const dbPath = `${orgDir}/operon-cli.db`;
  await assertQuiescent(dbPath);
  const { path: clone, cleanup } = await cloneDb(dbPath);
  try {
    const projects = (await readClone(clone, QUERIES.projects_all())) as Array<
      { id?: unknown; name?: unknown }
    >;
    const proj = projects.find((p) =>
      p.id === projectArg || p.name === projectArg
    );
    if (!proj) throw new Error(`no project matched '${projectArg}'`);
    const pid = String(proj.id);
    if (!PROJ_ID_RE.test(pid)) throw new Error(`unexpected project id: ${pid}`);

    const rows = (await readClone(
      clone,
      QUERIES.notifications_by_project(pid),
    )) as RawNotification[];
    const { notifications, byType } = buildNotifications(rows);

    const record: Notifications = {
      sensitive: true,
      session: pid,
      total: notifications.length,
      byType,
      notifications,
      origin: {
        tool: "claude-science",
        org,
        project: { id: pid, name: (proj.name ?? null) as string | null },
      },
    };
    NotificationsSchema.parse(record);
    const handle = await sink.writeResource("notifications", pid, record);
    sink.logger.info("capture_notifications done", {
      total: notifications.length,
      byType,
    });
    return { dataHandles: [handle] };
  } finally {
    await cleanup();
  }
}
