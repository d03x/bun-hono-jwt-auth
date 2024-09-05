/*
  Warnings:

  - You are about to alter the column `expiredAt` on the `RefreshToken` table. The data in that column could be lost. The data in that column will be cast from `VarChar(191)` to `Int`.

*/
-- AlterTable
ALTER TABLE `RefreshToken` MODIFY `expiredAt` INTEGER NOT NULL;
