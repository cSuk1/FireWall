-- MySQL dump 10.13  Distrib 8.0.35, for Linux (x86_64)
--
-- Host: 127.0.0.1    Database: db_firewall
-- ------------------------------------------------------
-- Server version	8.0.35-0ubuntu0.20.04.1

/*!40101 SET @OLD_CHARACTER_SET_CLIENT=@@CHARACTER_SET_CLIENT */;
/*!40101 SET @OLD_CHARACTER_SET_RESULTS=@@CHARACTER_SET_RESULTS */;
/*!40101 SET @OLD_COLLATION_CONNECTION=@@COLLATION_CONNECTION */;
/*!50503 SET NAMES utf8mb4 */;
/*!40103 SET @OLD_TIME_ZONE=@@TIME_ZONE */;
/*!40103 SET TIME_ZONE='+00:00' */;
/*!40014 SET @OLD_UNIQUE_CHECKS=@@UNIQUE_CHECKS, UNIQUE_CHECKS=0 */;
/*!40014 SET @OLD_FOREIGN_KEY_CHECKS=@@FOREIGN_KEY_CHECKS, FOREIGN_KEY_CHECKS=0 */;
/*!40101 SET @OLD_SQL_MODE=@@SQL_MODE, SQL_MODE='NO_AUTO_VALUE_ON_ZERO' */;
/*!40111 SET @OLD_SQL_NOTES=@@SQL_NOTES, SQL_NOTES=0 */;

--
-- Table structure for table `t_act`
--
CREATE DATABASE IF NOT EXISTS `db_firewall` /*!40100 DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci */ /*!80016 DEFAULT ENCRYPTION='N' */;
USE `db_firewall` ;
DROP TABLE IF EXISTS `t_act`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `t_act` (
  `create_time` datetime DEFAULT NULL COMMENT 'Create Time',
  `act` int DEFAULT NULL,
  `index` varchar(255) DEFAULT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_act`
--

/*!40000 ALTER TABLE `t_act` DISABLE KEYS */;
INSERT INTO `t_act` VALUES ('2023-12-02 20:19:39',1,'act');
/*!40000 ALTER TABLE `t_act` ENABLE KEYS */;

--
-- Table structure for table `t_filter_rules`
--

DROP TABLE IF EXISTS `t_filter_rules`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `t_filter_rules` (
  `id` int NOT NULL AUTO_INCREMENT COMMENT 'Primary Key',
  `create_time` datetime DEFAULT NULL COMMENT 'Create Time',
  `name` varchar(255) DEFAULT NULL,
  `src_ip` varchar(255) DEFAULT NULL,
  `dst_ip` varchar(255) DEFAULT NULL,
  `src_port` varchar(255) DEFAULT NULL,
  `dst_port` varchar(255) DEFAULT NULL,
  `protocol` varchar(255) DEFAULT NULL,
  `act` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=63 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_filter_rules`
--

/*!40000 ALTER TABLE `t_filter_rules` DISABLE KEYS */;
INSERT INTO `t_filter_rules` VALUES (61,'2023-11-27 16:52:33','disallow_ping','any','192.168.219.128/24','any','any','ICMP','re');
/*!40000 ALTER TABLE `t_filter_rules` ENABLE KEYS */;

--
-- Table structure for table `t_nat_rules`
--

DROP TABLE IF EXISTS `t_nat_rules`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `t_nat_rules` (
  `id` int NOT NULL AUTO_INCREMENT COMMENT 'Primary Key',
  `create_time` datetime DEFAULT NULL COMMENT 'Create Time',
  `seq` int DEFAULT NULL,
  `bf_ip` varchar(255) DEFAULT NULL,
  `af_ip` varchar(255) DEFAULT NULL,
  `min_port` int DEFAULT NULL,
  `max_port` int DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=28 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_nat_rules`
--

/*!40000 ALTER TABLE `t_nat_rules` DISABLE KEYS */;
INSERT INTO `t_nat_rules` VALUES (27,'2023-12-14 21:25:15',0,'192.168.18.128/24','192.168.5.129',0,65535);
/*!40000 ALTER TABLE `t_nat_rules` ENABLE KEYS */;

--
-- Table structure for table `t_users`
--

DROP TABLE IF EXISTS `t_users`;
/*!40101 SET @saved_cs_client     = @@character_set_client */;
/*!50503 SET character_set_client = utf8mb4 */;
CREATE TABLE `t_users` (
  `id` int NOT NULL AUTO_INCREMENT COMMENT 'Primary Key',
  `create_time` datetime DEFAULT NULL COMMENT 'Create Time',
  `username` varchar(255) CHARACTER SET utf8mb4 COLLATE utf8mb4_0900_ai_ci DEFAULT NULL,
  `password` varchar(255) DEFAULT NULL,
  `email` varchar(255) DEFAULT NULL,
  PRIMARY KEY (`id`)
) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_0900_ai_ci;
/*!40101 SET character_set_client = @saved_cs_client */;

--
-- Dumping data for table `t_users`
--

/*!40000 ALTER TABLE `t_users` DISABLE KEYS */;
INSERT INTO `t_users` VALUES (1,'2023-11-10 13:51:44','admin','d033e22ae348aeb5660fc2140aec35850c4da997','652240843@qq.com');
/*!40000 ALTER TABLE `t_users` ENABLE KEYS */;

--
-- Dumping routines for database 'db_firewall'
--
/*!40103 SET TIME_ZONE=@OLD_TIME_ZONE */;

/*!40101 SET SQL_MODE=@OLD_SQL_MODE */;
/*!40014 SET FOREIGN_KEY_CHECKS=@OLD_FOREIGN_KEY_CHECKS */;
/*!40014 SET UNIQUE_CHECKS=@OLD_UNIQUE_CHECKS */;
/*!40101 SET CHARACTER_SET_CLIENT=@OLD_CHARACTER_SET_CLIENT */;
/*!40101 SET CHARACTER_SET_RESULTS=@OLD_CHARACTER_SET_RESULTS */;
/*!40101 SET COLLATION_CONNECTION=@OLD_COLLATION_CONNECTION */;
/*!40111 SET SQL_NOTES=@OLD_SQL_NOTES */;

-- Dump completed on 2023-12-16 17:37:37
