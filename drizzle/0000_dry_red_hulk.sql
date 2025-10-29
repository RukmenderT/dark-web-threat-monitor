CREATE TABLE `monitored_urls` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`url` text NOT NULL,
	`type` text NOT NULL,
	`status` text NOT NULL,
	`risk_score` integer DEFAULT 0 NOT NULL,
	`threat_count` integer DEFAULT 0 NOT NULL,
	`scan_interval` integer DEFAULT 300 NOT NULL,
	`last_scan` integer,
	`next_scan` integer,
	`added_at` integer NOT NULL,
	`updated_at` integer
);
--> statement-breakpoint
CREATE TABLE `scan_history` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`url_id` integer NOT NULL,
	`scan_timestamp` integer NOT NULL,
	`risk_score` integer,
	`threats_found` integer,
	`scan_duration` integer,
	`status` text,
	FOREIGN KEY (`url_id`) REFERENCES `monitored_urls`(`id`) ON UPDATE no action ON DELETE no action
);
--> statement-breakpoint
CREATE TABLE `threat_findings` (
	`id` integer PRIMARY KEY AUTOINCREMENT NOT NULL,
	`url_id` integer NOT NULL,
	`category` text NOT NULL,
	`severity` text NOT NULL,
	`title` text NOT NULL,
	`description` text,
	`evidence` text,
	`remediation` text,
	`confidence_score` real DEFAULT 0 NOT NULL,
	`false_positive` integer DEFAULT false NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`url_id`) REFERENCES `monitored_urls`(`id`) ON UPDATE no action ON DELETE no action
);
