import { sqliteTable, integer, text, real } from 'drizzle-orm/sqlite-core';

export const monitoredUrls = sqliteTable('monitored_urls', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  url: text('url').notNull(),
  type: text('type').notNull(),
  status: text('status').notNull(),
  riskScore: integer('risk_score').notNull().default(0),
  threatCount: integer('threat_count').notNull().default(0),
  scanInterval: integer('scan_interval').notNull().default(300),
  lastScan: integer('last_scan'),
  nextScan: integer('next_scan'),
  addedAt: integer('added_at').notNull(),
  updatedAt: integer('updated_at'),
});

export const threatFindings = sqliteTable('threat_findings', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  urlId: integer('url_id').notNull().references(() => monitoredUrls.id),
  category: text('category').notNull(),
  severity: text('severity').notNull(),
  title: text('title').notNull(),
  description: text('description'),
  evidence: text('evidence'),
  remediation: text('remediation'),
  confidenceScore: real('confidence_score').notNull().default(0.0),
  falsePositive: integer('false_positive', { mode: 'boolean' }).notNull().default(false),
  createdAt: integer('created_at').notNull(),
});

export const scanHistory = sqliteTable('scan_history', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  urlId: integer('url_id').notNull().references(() => monitoredUrls.id),
  scanTimestamp: integer('scan_timestamp').notNull(),
  riskScore: integer('risk_score'),
  threatsFound: integer('threats_found'),
  scanDuration: integer('scan_duration'),
  status: text('status'),
});