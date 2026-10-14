import type { AlertKind, CheckId, CheckStatus, Grade } from "@bluebench/shared";
import { index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

/**
 * D1 schema. Migrations are generated from this file with `pnpm --filter @bluebench/api db:generate`
 * into ./migrations, and applied by CI before each deploy.
 *
 * The first four tables are Better Auth's (field names must match its model). We keep only what a
 * magic-link account needs: no IP addresses or user agents are stored (see auth.ts).
 */

const time = (name: string) => integer(name, { mode: "timestamp_ms" });

export const user = sqliteTable("user", {
  id: text("id").primaryKey(),
  name: text("name").notNull(),
  email: text("email").notNull().unique(),
  emailVerified: integer("email_verified", { mode: "boolean" }).notNull().default(false),
  image: text("image"),
  createdAt: time("created_at").notNull(),
  updatedAt: time("updated_at").notNull(),
  // Ours (Better Auth leaves it to its default). Email is the fallback when push can't reach the user.
  emailAlerts: integer("email_alerts", { mode: "boolean" }).notNull().default(true),
});

export const session = sqliteTable(
  "session",
  {
    id: text("id").primaryKey(),
    expiresAt: time("expires_at").notNull(),
    token: text("token").notNull().unique(),
    createdAt: time("created_at").notNull(),
    updatedAt: time("updated_at").notNull(),
    // Required by Better Auth's model; always null here.
    ipAddress: text("ip_address"),
    userAgent: text("user_agent"),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
  },
  (t) => [index("session_user_id").on(t.userId)],
);

/** Better Auth's account table. Magic-link sign-in doesn't create rows, but the adapter expects it. */
export const account = sqliteTable(
  "account",
  {
    id: text("id").primaryKey(),
    accountId: text("account_id").notNull(),
    providerId: text("provider_id").notNull(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    accessToken: text("access_token"),
    refreshToken: text("refresh_token"),
    idToken: text("id_token"),
    accessTokenExpiresAt: time("access_token_expires_at"),
    refreshTokenExpiresAt: time("refresh_token_expires_at"),
    scope: text("scope"),
    password: text("password"),
    createdAt: time("created_at").notNull(),
    updatedAt: time("updated_at").notNull(),
  },
  (t) => [index("account_user_id").on(t.userId)],
);

/** Pending magic links. The identifier is a hash of the token, never the token itself. */
export const verification = sqliteTable(
  "verification",
  {
    id: text("id").primaryKey(),
    identifier: text("identifier").notNull(),
    value: text("value").notNull(),
    expiresAt: time("expires_at").notNull(),
    createdAt: time("created_at").notNull(),
    updatedAt: time("updated_at").notNull(),
  },
  (t) => [index("verification_identifier").on(t.identifier)],
);

/** A saved domain. Monitored daily once `verifiedAt` is set (TXT record found). */
export const domain = sqliteTable(
  "domain",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    verifyToken: text("verify_token").notNull(),
    verifiedAt: time("verified_at"),
    /** Last daily check (or attempt). Null = due now. */
    lastCheckedAt: time("last_checked_at"),
    grade: text("grade").$type<Grade>(),
    score: integer("score"),
    /** Status of each check at the last daily run, to tell a real regression from a skipped check. */
    statuses: text("statuses", { mode: "json" }).$type<Partial<Record<CheckId, CheckStatus>>>(),
    certExpiresAt: time("cert_expires_at"),
    /** Smallest expiry threshold (30/14/7 days) already alerted for the current certificate. */
    certAlertedDays: integer("cert_alerted_days"),
    /** Lookalike watcher: position in the variant list of the scan in progress (0 = start a new one). */
    lookalikeCursor: integer("lookalike_cursor").notNull().default(0),
    /** When the last full lookalike scan finished. Null = never; the first scan sets a baseline without alerts. */
    lookalikeScannedAt: time("lookalike_scanned_at"),
    /** Last lookalike chunk run (or attempt), so domains take turns. */
    lookalikeCheckedAt: time("lookalike_checked_at"),
    createdAt: time("created_at").notNull(),
  },
  (t) => [uniqueIndex("domain_user_name").on(t.userId, t.name), index("domain_due").on(t.verifiedAt, t.lastCheckedAt)],
);

/** A lookalike of a saved domain that has a website (A record) or mail (MX). Deleted once it stops resolving. */
export const lookalike = sqliteTable(
  "lookalike",
  {
    id: text("id").primaryKey(),
    domainId: text("domain_id")
      .notNull()
      .references(() => domain.id, { onDelete: "cascade" }),
    name: text("name").notNull(),
    web: integer("web", { mode: "boolean" }).notNull(),
    mail: integer("mail", { mode: "boolean" }).notNull(),
    firstSeenAt: time("first_seen_at").notNull(),
    lastSeenAt: time("last_seen_at").notNull(),
  },
  (t) => [uniqueIndex("lookalike_domain_name").on(t.domainId, t.name)],
);

/** Alert history. Rows with no `deliveredAt` are waiting for the cron to send them. */
export const alert = sqliteTable(
  "alert",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    domainId: text("domain_id").references(() => domain.id, { onDelete: "set null" }),
    /** Kept so the history still reads well after the domain is removed. */
    domain: text("domain"),
    kind: text("kind").$type<AlertKind>().notNull(),
    title: text("title").notNull(),
    body: text("body").notNull(),
    createdAt: time("created_at").notNull(),
    deliveredAt: time("delivered_at"),
    channel: text("channel").$type<"push" | "email" | "none">(),
    attempts: integer("attempts").notNull().default(0),
  },
  (t) => [index("alert_pending").on(t.deliveredAt), index("alert_user_created").on(t.userId, t.createdAt)],
);

/** A browser's Web Push subscription. The endpoint is checked against known push services. */
export const pushSubscription = sqliteTable(
  "push_subscription",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    endpoint: text("endpoint").notNull().unique(),
    p256dh: text("p256dh").notNull(),
    auth: text("auth").notNull(),
    createdAt: time("created_at").notNull(),
  },
  (t) => [index("push_subscription_user_id").on(t.userId)],
);

/** A vendor (product null) or product an account watches for new known exploited vulnerabilities. */
export const watch = sqliteTable(
  "watch",
  {
    id: text("id").primaryKey(),
    userId: text("user_id")
      .notNull()
      .references(() => user.id, { onDelete: "cascade" }),
    /** As KEV names it, for display. */
    vendor: text("vendor").notNull(),
    product: text("product"),
    /** Lowercased vendor, for matching new KEV entries. */
    vendorKey: text("vendor_key").notNull(),
    /** Lowercased product, "" for a whole-vendor watch: with vendorKey, makes each logical watch unique. */
    productKey: text("product_key").notNull().default(""),
    createdAt: time("created_at").notNull(),
  },
  (t) => [
    index("watch_user").on(t.userId),
    index("watch_vendor_key").on(t.vendorKey),
    uniqueIndex("watch_user_vendor_product").on(t.userId, t.vendorKey, t.productKey),
  ],
);

/** KEV entries the watchlist cron has already handled, so each one alerts at most once. Pruned after 120 days. */
export const kevSeen = sqliteTable("kev_seen", {
  cve: text("cve").primaryKey(),
  seenAt: time("seen_at").notNull(),
});

/** Small key/value state for the intel cron (e.g. the KEV document version last processed). */
export const intelState = sqliteTable("intel_state", {
  key: text("key").primaryKey(),
  value: text("value").notNull(),
});

/** Latest result of each watchdog check (monitor/watchdog.ts). */
export const healthCheck = sqliteTable("health_check", {
  id: text("id").primaryKey(),
  ok: integer("ok", { mode: "boolean" }).notNull(),
  /** "off" when the source isn't configured; otherwise a short reason or result. */
  detail: text("detail").notNull(),
  checkedAt: time("checked_at").notNull(),
  /** First run of the current failure streak; null while passing. */
  failingSince: time("failing_since"),
  /** Consecutive failed runs. */
  failures: integer("failures").notNull().default(0),
  /** True once the owner was told about the current streak (so recovery can be announced). */
  alerted: integer("alerted", { mode: "boolean" }).notNull().default(false),
});
