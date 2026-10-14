ALTER TABLE `watch` ADD `product_key` text DEFAULT '' NOT NULL;--> statement-breakpoint
-- Hand-added: fill the new key for existing rows, then drop any duplicate logical watches, before the unique index.
UPDATE `watch` SET `product_key` = lower(trim(coalesce(`product`, '')));--> statement-breakpoint
DELETE FROM `watch` WHERE rowid NOT IN (SELECT min(rowid) FROM `watch` GROUP BY `user_id`, `vendor_key`, `product_key`);--> statement-breakpoint
CREATE UNIQUE INDEX `watch_user_vendor_product` ON `watch` (`user_id`,`vendor_key`,`product_key`);
