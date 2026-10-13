CREATE TABLE `intel_state` (
	`key` text PRIMARY KEY NOT NULL,
	`value` text NOT NULL
);
--> statement-breakpoint
CREATE TABLE `kev_seen` (
	`cve` text PRIMARY KEY NOT NULL,
	`seen_at` integer NOT NULL
);
--> statement-breakpoint
CREATE TABLE `watch` (
	`id` text PRIMARY KEY NOT NULL,
	`user_id` text NOT NULL,
	`vendor` text NOT NULL,
	`product` text,
	`vendor_key` text NOT NULL,
	`created_at` integer NOT NULL,
	FOREIGN KEY (`user_id`) REFERENCES `user`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE INDEX `watch_user` ON `watch` (`user_id`);--> statement-breakpoint
CREATE INDEX `watch_vendor_key` ON `watch` (`vendor_key`);