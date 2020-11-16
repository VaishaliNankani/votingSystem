// Copyright 2020 (C), Oracle and/or its affiliates. All rights reserved.
package com.oracle.cgbu.cne.nrf.hooks.releases;

import java.sql.SQLException;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import com.oracle.cgbu.cne.nrf.hooks.postinstall.PostInstallConfiguration;
import com.oracle.releasemanagement.Release;
import com.oracle.releasemanagement.ReleaseHooks;
import com.oracle.releasemanagement.ReleaseVersion;

@Component
public class ReleaseHelmHook_0_0_0 extends Release implements ReleaseHooks {

	private static final Logger logger = LogManager.getLogger(ReleaseHelmHook_0_0_0.class);
	@Autowired
	PostInstallConfiguration configureNrf;
	/*
     * Assigned the release-version (0,0,0) based on the ReadMe file mentioned
     * in the upgrade-common jar.
     */
	@Override
	public ReleaseVersion getReleaseVersion() {
		// TODO Auto-generated method stub
		return new ReleaseVersion(0, 0, 0);
	}

	/*
	 * As per the ReadMe file of upgrade-common:
	 * preUpgrade function will be getting called for
	 * pre-install as well as pre-upgrade hook invocations
	 */
	@Override
	public void preUpgrade() {
		Map<String, Object> logMsg = new LinkedHashMap<String, Object>();
		String applicationDatabase = getServiceDatabase();
		logMsg.clear();
		logMsg.put("logMsg", "Entering Function preUpgrade()");
		logMsg.put("applicationDatabase", applicationDatabase);
		logger.info(logMsg.toString());
		String batchSqls[]  = new String[3];
		
		batchSqls[0] = "CREATE TABLE IF NOT EXISTS `" + applicationDatabase + "`.`NfScreening` " +
				"(recordOwner VARCHAR(36) not null , " +
                "nfScreeningRulesListType varchar(30) not null, " +
                "nfScreeningType varchar(30) not null," +
                "nfScreeningRulesListStatus varchar(30) NOT NULL DEFAULT 'DISABLED'," +
                "nfScreeningJsonDocList JSON not null," +
                "lastUpdateTimestamp BIGINT not null," +
                "primary key (recordOwner,nfScreeningRulesListType))DEFAULT CHARSET=utf8;";


		batchSqls[1] = "CREATE TABLE IF NOT EXISTS `" + applicationDatabase + "`.`NrfSystemOptions` " +
				  " (configType VARCHAR(30) not null ," +
	                "recordOwner VARCHAR(36) not null , " +
	                "configurationJsonDocList JSON not null , " +
	                "lastUpdateTimestamp BIGINT  not null, " +
	                "primary key (configType,recordOwner))DEFAULT CHARSET=utf8;";


		
		batchSqls[2] = "CREATE TABLE IF NOT EXISTS `" + applicationDatabase + "`.`NrfEventTransactions` " +
				"(recordCreator VARCHAR(36) not null ," +
				"creationTimestamp BIGINT not null , " +
				"eventDetails JSON not null , " +				
			    "primary key (recordCreator,creationTimestamp))DEFAULT CHARSET=utf8;";
		try {
			sqlUtils.executeBatch(batchSqls);
		} catch (SQLException e) {
			logMsg.clear();
			logMsg.put("logMsg", "Error occured during table creation");
			logMsg.put("applicationDatabase", applicationDatabase);
			logMsg.put("SQL Statements Executed", batchSqls);
			logMsg.put("Exception", Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
			
		}
		createBackupTables();
		siteJsonSchemaVersionInfo.registerTableWithJsonSchemaVersion("NfScreening", "v1");
        siteJsonSchemaVersionInfo.registerTableWithJsonSchemaVersion("NrfSystemOptions", "v1");
        siteJsonSchemaVersionInfo.registerTableWithJsonSchemaVersion("NrfEventTransactions", "v1");
        logMsg.clear();
		logMsg.put("logMsg", "Exit from preUpgrade() function");
		logger.info(logMsg.toString());
	}
	
	@Override
	public void postDelete()
	{
		String applicationDatabase = getServiceDatabase();
		String  siteId = getNrfInstanceId();
		Map<String, Object> logMsg = new LinkedHashMap<String, Object>();
		logMsg.clear();
		logMsg.put("logMsg", "Inside Function postDelete()");
		logMsg.put("applicationDatabase", applicationDatabase);
		logMsg.put("siteId", siteId);
		logger.info(logMsg.toString());
		String[] batchSqls = new String[2];
		batchSqls[0] = "DELETE from `" + applicationDatabase + "`.`NrfSystemOptions` where recordOwner='"+siteId+"';";
		batchSqls[1] = "DELETE from `" + applicationDatabase + "`.`NfScreening` where recordOwner='"+siteId+"';";
		batchSqls[1] = "DELETE from `" + applicationDatabase + "`.`NrfEventTransactions` where recordCreator='"+siteId+"';";
		try {
			sqlUtils.executeBatch(batchSqls);
		} catch (SQLException e) {
			logMsg.clear();
			logMsg.put("logMsg", "Error occured during deletion of entries from table");
			logMsg.put("applicationDatabase", applicationDatabase);
			logMsg.put("siteId", siteId);
			logMsg.put("SQL Statements Executed", batchSqls);			
			logMsg.put("Exception", Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
		}
	}
	private String getNetworkDatabase() {
		String database = System.getenv("MYSQL_RELEASE_DATABASE");
		if (database != null && !database.isEmpty()) {
			return database;
		} else {
			this.logger.error("MYSQL_RELEASE_DATABASE environment variable is not configured.");
			throw new NullPointerException();
		}
	}
	private String getNrfInstanceId() {
		String nrfInstanceId = System.getenv("NF_INSTANCE_ID");
		if (nrfInstanceId != null && !nrfInstanceId.isEmpty()) {
			return nrfInstanceId;
		} else {
			this.logger.error("NF_INSTANCE_ID environment variable is not configured.");
			throw new NullPointerException();
		}
	}
	private void createBackupTables()
	{
		String networkDatabase = getNetworkDatabase();
		Map<String, Object> logMsg = new LinkedHashMap<String, Object>();
		logMsg.clear();
		logMsg.put("logMsg", "Inside Function createBackupTables()");
		logMsg.put("networkDatabase", networkDatabase);
		logger.info(logMsg.toString());
		String[] batchSqls = new String[2];
		batchSqls[0] = "CREATE TABLE IF NOT EXISTS `" + networkDatabase + "`.`NrfSystemOptions_backup` " +
				 " (configType VARCHAR(30) not null ," +
	                "recordOwner VARCHAR(36) not null , " +
	                "configurationJsonDocList JSON not null , " +
	                "lastUpdateTimestamp BIGINT  not null, " +
	                "releaseVersion int(11) not null)DEFAULT CHARSET=utf8;";
		
		batchSqls[1] = "CREATE TABLE IF NOT EXISTS `" + networkDatabase + "`.`NfScreening_backup` " +
				"( recordOwner VARCHAR(36) not null , " +
                "nfScreeningRulesListType varchar(30) not null, " +
                "nfScreeningType varchar(30) not null," +
                "nfScreeningRulesListStatus varchar(30) NOT NULL DEFAULT 'DISABLED'," +
                "nfScreeningJsonDocList JSON not null," +
                "lastUpdateTimestamp BIGINT not null," +
                "releaseVersion int(11) not null)DEFAULT CHARSET=utf8;";
		try {
			sqlUtils.executeBatch(batchSqls);
		} catch (SQLException e) {
			logMsg.clear();
			logMsg.put("logMsg", "Error occured whiel creating backup table");
			logMsg.put(networkDatabase, networkDatabase);	
			logMsg.put("SQL Statements Executed", batchSqls);
			logMsg.put("Exception", Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
		}
		logMsg.clear();
		logMsg.put("logMsg", "Successfully created backupTables");		
		logger.info(logMsg.toString());
	}
	
	@Override
	public void postUpgrade()
	{
		configureNrf.postInstallConfig();
	}
	
	

}
