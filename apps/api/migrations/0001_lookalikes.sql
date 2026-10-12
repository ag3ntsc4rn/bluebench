CREATE TABLE `lookalike` (
	`id` text PRIMARY KEY NOT NULL,
	`domain_id` text NOT NULL,
	`name` text NOT NULL,
	`web` integer NOT NULL,
	`mail` integer NOT NULL,
	`first_seen_at` integer NOT NULL,
	`last_seen_at` integer NOT NULL,
	FOREIGN KEY (`domain_id`) REFERENCES `domain`(`id`) ON UPDATE no action ON DELETE cascade
);
--> statement-breakpoint
CREATE UNIQUE INDEX `lookalike_domain_name` ON `lookalike` (`domain_id`,`name`);--> statement-breakpoint
ALTER TABLE `domain` ADD `lookalike_cursor` integer DEFAULT 0 NOT NULL;--> statement-breakpoint
ALTER TABLE `domain` ADD `lookalike_scanned_at` integer;--> statement-breakpoint
ALTER TABLE `domain` ADD `lookalike_checked_at` integer;