CREATE TABLE `health_check` (
	`id` text PRIMARY KEY NOT NULL,
	`ok` integer NOT NULL,
	`detail` text NOT NULL,
	`checked_at` integer NOT NULL,
	`failing_since` integer,
	`failures` integer DEFAULT 0 NOT NULL,
	`alerted` integer DEFAULT false NOT NULL
);
