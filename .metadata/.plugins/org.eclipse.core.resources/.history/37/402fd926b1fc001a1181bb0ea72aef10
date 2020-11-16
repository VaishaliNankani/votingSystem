// Copyright 2018 (C), Oracle and/or its affiliates. All rights reserved.
package com.oracle.cgbu.cne.common.service;


import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import org.apache.logging.log4j.ThreadContext;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.oracle.cgbu.cne.common.ConfigException;
import com.oracle.cgbu.cne.common.config.ConfigurationInfo;
import com.oracle.cgbu.cne.common.config.ConfigurationInfo.Oauthconfig;
import com.oracle.cgbu.cne.common.config.ConfigurationInfo.Sslconfig;
import com.oracle.cgbu.cne.common.service.client.CertReloadClientImpl;


@Service
public class UpdateConfiguration {

	private static Logger logger = LogManager.getLogger(UpdateConfiguration.class);

	@Value("${gateway.certReloadEnabled}")
	private boolean gatewayCertReloadEnabled;
	
	
	@Autowired(required= false)
	CertReloadClientImpl reloadClient;
	
	@Autowired
	private ConfigurationInfo configInfo;
	
	//private  ApiClient client;
	//maping of namespace to secrets
	Map<String, ArrayList<String>> sslK8Resources;
	Map<String,ArrayList<String> > oauthK8Resources;

	private  String resourceVersion ;	

    public void fillThreadContext(String ServiceOperation) {
		String nrfTxId = "nrf-tx-" + (int)(Math.random()*Integer.MAX_VALUE);
		ThreadContext.clearMap();
		ThreadContext.put("nrfTxId", nrfTxId);
		ThreadContext.put("subsystem",  ServiceOperation);
		ThreadContext.put("hostname", System.getenv("HOSTNAME"));
	}

        
	//static CoreV1Api api;
	public UpdateConfiguration() {			
        this.sslK8Resources = new HashMap<String, ArrayList<String>>();
		this.oauthK8Resources = new HashMap<String, ArrayList<String>>();
	}

	public ConfigurationInfo getConfigInfo() {
		return configInfo;
	}
	@Autowired
	public void setConfigInfo(ConfigurationInfo config) {
		fillThreadContext("UpdateService");
		if (config == null || (config.getSslConfig() == null && config.getOauthConfig()== null)) {
			logger.error("Bad configuration. Missing 'ssl/oauth' configuration.\"");
			throw new ConfigException("Bad configuration. one of the ssl/oauth configuration should be present.");
		}
		//add validation for ssl and oauth configuration received through helm		
		this.configInfo = config;
		fillSslNamespacesAndSecrets();
		fillOauthNamespacesAndSecrets();
		monitorConfigurationUpdate();
	}


	public String getResourceVersion() {
		return resourceVersion;
	}

	public void setResourceVersion(String resourceVersion) {
		this.resourceVersion = resourceVersion;
	}


	public Map<String, ArrayList<String>> getSslK8Resources() {
		return sslK8Resources;
	}

	public void setSslK8Resources(Map<String, ArrayList<String>> sslK8Resources) {
		this.sslK8Resources = sslK8Resources;
	}

	public Map<String, ArrayList<String>> getOauthK8Resources() {
		return oauthK8Resources;
	}

	public void setOauthK8Resources(Map<String, ArrayList<String>> oauthK8Resources) {
		this.oauthK8Resources = oauthK8Resources;
	}

	public void  fillOauthNamespacesAndSecrets()
	{

		Map<String, ArrayList<String>> oauthResource = getOauthK8Resources();
		Oauthconfig oauthConfig = this.getConfigInfo().getOauthConfig();

		if(!oauthResource.containsKey(oauthConfig.getKeyStorePasswordSecretNameSpace()))
		{
			ArrayList<String> list= new ArrayList<String>();
			list.add(oauthConfig.getKeyStorePasswordSecretName());
			oauthResource.put(oauthConfig.getKeyStorePasswordSecretNameSpace() , list);

		}
		else
		{   
			ArrayList<String> list = oauthResource.get(oauthConfig.getKeyStorePasswordSecretNameSpace());
			if(!list.contains(oauthConfig.getKeyStorePasswordSecretName()))
			{
				list.add(oauthConfig.getKeyStorePasswordSecretName());
			}
		}

		//putting certificate namespace

		if(!oauthResource.containsKey(oauthConfig.getCertificateSecretNameSpace()))
		{
			ArrayList<String> list= new ArrayList<String>();
			list.add(oauthConfig.getCertificateSecretName());
			oauthResource.put(oauthConfig.getCertificateSecretNameSpace() , list);
		}
		else
		{  
			ArrayList<String> list = oauthResource.get(oauthConfig.getCertificateSecretNameSpace());
			if(!list.contains(oauthConfig.getCertificateSecretName()))
			{
				list.add(oauthConfig.getCertificateSecretName());
			}
		}

		//putting private namespace

		if(!oauthResource.containsKey(oauthConfig.getPrivateKeySecretNameSpace()))
		{  
			ArrayList<String> list= new ArrayList<String>();
			list.add(oauthConfig.getPrivateKeySecretName());
			oauthResource.put(oauthConfig.getPrivateKeySecretNameSpace(), list);
		}
		else
		{
			ArrayList<String> list = oauthResource.get(oauthConfig.getPrivateKeySecretNameSpace());
			if(!list.contains(oauthConfig.getPrivateKeySecretName()))
			{
				list.add(oauthConfig.getPrivateKeySecretName());
			}
		}

	}
	public void  fillSslNamespacesAndSecrets()
	{
		Sslconfig sslConfig = this.getConfigInfo().getSslConfig();

		Map<String, ArrayList<String>> sslResource = getSslK8Resources();

		//putting cabundle namespace

		if(!sslResource.containsKey(sslConfig.getCaBundleSecretNameSpace()))
		{
			ArrayList<String> list= new ArrayList<String>();
			list.add(sslConfig.getCaBundleSecretName());
			sslResource.put(sslConfig.getCaBundleSecretNameSpace() , list);
		}
		else
		{
			ArrayList<String> list = sslResource.get(sslConfig.getCaBundleSecretNameSpace());
			if(!list.contains(sslConfig.getCaBundleSecretName()))
			{
				list.add(sslConfig.getCaBundleSecretName());
			}
		}
		//putting truststore namespace

		if(!sslResource.containsKey(sslConfig.getTrustStorePasswordSecretNameSpace()))
		{
			ArrayList<String> list= new ArrayList<String>();
			list.add(sslConfig.getTrustStorePasswordSecretName());
			sslResource.put(sslConfig.getTrustStorePasswordSecretNameSpace() , list);
		}
		else
		{
			ArrayList<String> list = sslResource.get(sslConfig.getTrustStorePasswordSecretNameSpace());
			if(!list.contains(sslConfig.getTrustStorePasswordSecretName()))
			{
				list.add(sslConfig.getTrustStorePasswordSecretName());
			}
		}

		//putting keystore  namespace

		if(!sslResource.containsKey(sslConfig.getKeyStorePasswordSecretNameSpace()))
		{
			ArrayList<String> list= new ArrayList<String>();
			list.add(sslConfig.getKeyStorePasswordSecretName());

			sslResource.put(sslConfig.getKeyStorePasswordSecretNameSpace() , list);

		}
		else
		{
			ArrayList<String> list = sslResource.get(sslConfig.getKeyStorePasswordSecretNameSpace());
			if(!list.contains(sslConfig.getKeyStorePasswordSecretName()))
			{
				list.add(sslConfig.getKeyStorePasswordSecretName());
			}
		}


		//putting certificate namespace

		if(!sslResource.containsKey(sslConfig.getCertificateSecretNameSpace()))
		{
			ArrayList<String> list= new ArrayList<String>();
			list.add(sslConfig.getCertificateSecretName());
			sslResource.put(sslConfig.getCertificateSecretNameSpace() , list);
		}
		else
		{
			ArrayList<String> list = sslResource.get(sslConfig.getCertificateSecretNameSpace());
			if(!list.contains(sslConfig.getCertificateSecretName()))
			{
				list.add(sslConfig.getCertificateSecretName());
			}
		}

		//putting private namespace

		if(!sslResource.containsKey(sslConfig.getPrivateKeySecretNameSpace()))
		{
			ArrayList<String> list= new ArrayList<String>();
			list.add(sslConfig.getPrivateKeySecretName());
			sslResource.put(sslConfig.getPrivateKeySecretNameSpace(), list);
		}
		else
		{   
			ArrayList<String> list = sslResource.get(sslConfig.getPrivateKeySecretNameSpace());
			if(!list.contains(sslConfig.getPrivateKeySecretName()))
			{
				list.add(sslConfig.getPrivateKeySecretName());
			}
		}
	}


	public void monitorConfigurationUpdate()
	{

		if(this.getConfigInfo().getGlobalConfig().getInitSsl() == true)
		{
			monitorSslConfigurationUpdate();
		}
		else
		{
			monitorOauthConfigurationUpdate();
		}

	}

	public void monitorSslConfigurationUpdate()
	{
		logger.info("monitor ssl configuration");
		Map<String, ArrayList<String>> sslResource  = this.getSslK8Resources();
		logger.info("number of namespaces to monitor"+sslResource.keySet().size());
		ExecutorService executor = Executors.newFixedThreadPool(sslResource.keySet().size());
		for (Map.Entry<String,ArrayList<String>> entry : sslResource.entrySet()) {

			ConfigWatchProcess sslUpdateworker = new ConfigWatchProcess(this, 
					entry.getKey() , entry.getValue(),getConfigInfo(),"SSL",reloadClient) ;
			executor.execute(sslUpdateworker);
		}

	}
	public void monitorOauthConfigurationUpdate()
	{

		logger.info("monitor oauth configuration");
		Map<String, ArrayList<String>> oauthResource  = this.getOauthK8Resources();
		logger.info("number of namespaces to monitor"+oauthResource.keySet().size());
		ExecutorService executor = Executors.newFixedThreadPool(oauthResource.keySet().size());
		for (Map.Entry<String,ArrayList<String>> entry : oauthResource.entrySet()) {
			ConfigWatchProcess oauthUpdateworker = new ConfigWatchProcess(this, 
					entry.getKey() , entry.getValue(),getConfigInfo(),"OAUTH",reloadClient) ;
			executor.execute(oauthUpdateworker);
		}
	}

}


