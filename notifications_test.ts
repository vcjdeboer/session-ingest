import { assertEquals } from "jsr:@std/assert@1";
import { buildNotifications } from "./notifications.ts";

Deno.test("buildNotifications: tallies by type, coerces payload, derives read", () => {
  const { notifications, byType } = buildNotifications([
    {
      sender_frame_id: "a",
      recipient_frame_id: "b",
      root_frame_id: "r",
      notification_type: "task",
      payload: '{"x":1}',
      read_at: 123,
      created_at: 10,
    },
    {
      sender_frame_id: "b",
      recipient_frame_id: "a",
      root_frame_id: "r",
      notification_type: "result",
      payload: { done: true }, // object payload -> JSON.stringify
      read_at: null, // unread
      created_at: 20,
    },
    {
      notification_type: "task",
      payload: null, // null payload -> ""
    },
  ]);

  assertEquals(byType, { task: 2, result: 1 });
  assertEquals(notifications.length, 3);

  assertEquals(notifications[0].payload, '{"x":1}');
  assertEquals(notifications[0].read, true);
  assertEquals(notifications[0].createdAt, 10);

  assertEquals(notifications[1].payload, '{"done":true}');
  assertEquals(notifications[1].read, false);

  assertEquals(notifications[2].payload, "");
  assertEquals(notifications[2].senderFrameId, null);
  assertEquals(notifications[2].read, false);
});

Deno.test("buildNotifications: empty input", () => {
  const { notifications, byType } = buildNotifications([]);
  assertEquals(notifications, []);
  assertEquals(byType, {});
});
