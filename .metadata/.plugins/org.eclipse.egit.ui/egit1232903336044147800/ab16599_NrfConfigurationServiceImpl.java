// Copyright 2018 (C), Oracle and/or its affiliates. All rights reserved.

package com.oracle.cgbu.cne.nrf.service;

import java.io.StringReader;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.json.Json;
import javax.json.JsonObject;
import javax.validation.Validation;
import javax.validation.Validator;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.core.config.Configurator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.RequestMethod;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.oracle.cgbu.cne.nrf.NrfConfigException;
import com.oracle.cgbu.cne.nrf.NrfException;
import com.oracle.cgbu.cne.nrf.annotations.NFType;
import com.oracle.cgbu.cne.nrf.config.NrfConfigurations;
import com.oracle.cgbu.cne.nrf.dao.NfScreening;
import com.oracle.cgbu.cne.nrf.dao.NfScreeningRepository;
import com.oracle.cgbu.cne.nrf.dao.NrfEventTransactionsDao;
import com.oracle.cgbu.cne.nrf.dao.NrfEventTransactionsRepository;
import com.oracle.cgbu.cne.nrf.dao.NrfSystemOptionsDao;
import com.oracle.cgbu.cne.nrf.dao.NrfSystemOptionsRepository;
import com.oracle.cgbu.cne.nrf.domain.AuthFeatureConfig;
import com.oracle.cgbu.cne.nrf.domain.ErrorInfo;
import com.oracle.cgbu.cne.nrf.domain.ErrorResponses;
import com.oracle.cgbu.cne.nrf.domain.FeatureStatus;
import com.oracle.cgbu.cne.nrf.domain.ForwardingSystemOptions;
import com.oracle.cgbu.cne.nrf.domain.InvalidParam;
import com.oracle.cgbu.cne.nrf.domain.NfConfig;
import com.oracle.cgbu.cne.nrf.domain.NfDiscoverSystemOptions;
import com.oracle.cgbu.cne.nrf.domain.NfScreeningRules;
import com.oracle.cgbu.cne.nrf.domain.NfScreeningRulesList;
import com.oracle.cgbu.cne.nrf.domain.NfScreeningRulesListStatus;
import com.oracle.cgbu.cne.nrf.domain.NfScreeningRulesListType;
import com.oracle.cgbu.cne.nrf.domain.NrfEngSystemOptions;
import com.oracle.cgbu.cne.nrf.domain.NrfEventDetails;
import com.oracle.cgbu.cne.nrf.domain.NrfEventResponse;
import com.oracle.cgbu.cne.nrf.domain.NrfSystemOptions;
import com.oracle.cgbu.cne.nrf.domain.PatchItem;
import com.oracle.cgbu.cne.nrf.domain.ProblemDetails;
import com.oracle.cgbu.cne.nrf.domain.ScreeningRulesResult;
import com.oracle.cgbu.cne.nrf.domain.SlfSystemOptions;
import com.oracle.cgbu.cne.nrf.metrics.CommonNrfMetrics;
import com.oracle.cgbu.cne.nrf.metrics.MetricsDimension;

@Service
public class NrfConfigurationServiceImpl implements NrfConfigurationService {
	private static Logger logger = LogManager.getLogger(NrfConfigurationServiceImpl.class);

	@Autowired
	NfScreeningRepository nfScreeningRepository;

	@Autowired
	private NrfConfigurations nrfConfig;

	@Autowired
	private NrfSystemOptionsRepository nrfSystemOptionsRepository;
	
	@Autowired
	private NrfEventTransactionsRepository nrfEventTransactionsRepository;
	
	@Autowired
	private CommonNrfMetrics commonNrfMetrics;

	@Autowired
	private MetricsDimension metricsDimension;
	
	public MetricsDimension getMetricsDimension() {
		return metricsDimension;
	}

	public void setMetricsDimension(MetricsDimension metricsDimension) {
		this.metricsDimension = metricsDimension;
	}

	public CommonNrfMetrics getCommonNrfMetrics() {
		return commonNrfMetrics;
	}

	public void setCommonNrfMetrics(CommonNrfMetrics commonNrfMetrics) {
		this.commonNrfMetrics = commonNrfMetrics;
	}

	private int maxCount = 1000;
	
	private static String NRF_SYSTEMOPTIONS="NrfSystemOptions";
	private static String NF_SCREENING="NfScreening";
	private static String serviceOperation="NrfConfiguration";
	private static String FIND="find";
	private static String VERSION="v1";
	private static String UPDATE="update";
	private static String CREATE="create";

	public NrfConfigurationServiceImpl() {

	}

	@Autowired
	public void setNrfConfig(NrfConfigurations config) {
		if(config==null || config.getConfSvc()==null) {
			throw new NrfConfigException("Bad NRF configuration. Missing 'nrf.conf-svc.*' properties.");
		}
		if(config.getGlobalConfig().getNrfInstanceId()==null) {
			throw new NrfConfigException("Bad NRF configuration. Missing 'nrf.nrf-instance-id' properties.");
		}
		this.nrfConfig = config;
		this.maxCount = nrfConfig.getMaxCount();
	}

	@Override
	public Object updateNfScreeningRules(NfScreeningRulesListType ruleListType, NfScreeningRules nfScreeningRules) {
		Map<String, Object> logMsg = new LinkedHashMap<String, Object>();
		logMsg.clear();
		logMsg.put("logMsg", "updateNfScreeningRules called with nfScreeningRules");
		logMsg.put("nfScreeningRules",nfScreeningRules);
		logger.info(logMsg.toString());

		nfScreeningRules.setNfScreeningRulesListType(ruleListType);

		// validation
		try {
			nfScreeningRules.semanticValidation(this.maxCount);
		}catch (NrfException e) {
			ProblemDetails prob = e.getProbDetails();
			logMsg.clear();
			logMsg.put("logMsg", "updateNfScreeningRules failed with problemDetails");
			logMsg.put("problemDetails",prob);
			logger.error(logMsg.toString());
			return prob;
		}

		NfScreening nfScreening;
		NfScreening savedNfScreening=null;
		NfScreening oldNfScreening=null;
		metricsDimension.setMethod(RequestMethod.PUT);
		try {
			try {
			oldNfScreening = nfScreeningRepository.findByRecordOwnerAndNfScreeningRulesListType(this.nrfConfig.getGlobalConfig().getNrfInstanceId(),ruleListType);
			commonNrfMetrics.pegNrfDbMetricsSuccessTotal(RequestMethod.PUT, FIND, serviceOperation, NF_SCREENING);
			}catch(Exception e){
				commonNrfMetrics.pegNrfDbMetricsFailuresTotal(RequestMethod.PUT, FIND, serviceOperation,e, NF_SCREENING);
			}
			//constructor for retaining old additional attributes values
			nfScreening = new NfScreening(oldNfScreening,nfScreeningRules);
			metricsDimension.setDbOperation("update");
			try {
			savedNfScreening = nfScreeningRepository.saveAndFlush(nfScreening);
			commonNrfMetrics.pegNrfDbMetricsSuccessTotal(RequestMethod.PUT, UPDATE, serviceOperation, NF_SCREENING);
			}catch(Exception e) {
				commonNrfMetrics.pegNrfDbMetricsFailuresTotal(RequestMethod.PUT, UPDATE, serviceOperation, e, NF_SCREENING);
			}
			if(savedNfScreening != null) {
				NfScreeningRules savedNfScreeningRules = (NfScreeningRules) nfScreening.toDomain(VERSION);
				logMsg.clear();
				logMsg.put("logMsg", "Successfully updated NfScreeningRules");
				logMsg.put("updatedNfScreeningRules",savedNfScreeningRules);
				logger.warn(logMsg.toString());
				//setting additional attributes as null for operator
				savedNfScreeningRules.setAdditionalAttributes(null);
				return savedNfScreeningRules;
			}
			else {
				ProblemDetails prob = ProblemDetails.forInternalError();
				prob.setCause("Could not update NfScreeningRules");
				logMsg.clear();
				logMsg.put("logMsg", "NfScreeningRules updation failed");
				logger.error(logMsg.toString());
				return prob;
			}
		}
		catch (Exception e) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not update NfScreeningRules due to an unexpected error.");
			logMsg.clear();
			logMsg.put("logMsg", e.getMessage());
			logMsg.put("problemDetails",Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
			return prob;
		}
	}

	@Override
	public Object getAllNfScreeningRules(NfScreeningRulesListType  nfScreeningRulesListType, NfScreeningRulesListStatus  nfScreeningRulesListStatus) {
		Map<String, Object> logMsg = new LinkedHashMap<String, Object>();
		logMsg.clear();
		logMsg.put("logMsg", "getAllNfScreeningRules called");
		logger.info(logMsg.toString());

		ScreeningRulesResult screeningRulesResult = new ScreeningRulesResult();
		List<NfScreening> nfScreeningList = new ArrayList<NfScreening>();
		List<NfScreeningRules> nfScreeningRulesList = new ArrayList<NfScreeningRules>();
		List<NfScreeningRules> nfScreeningRulesListWithAdditionalAttributes = new ArrayList<NfScreeningRules>();
		metricsDimension.setMethod(RequestMethod.GET);
		try {
			if((nfScreeningRulesListType == null) && (nfScreeningRulesListStatus == null)) {
				try {
				nfScreeningList = nfScreeningRepository.findAll();
				commonNrfMetrics.pegNrfDbMetricsSuccessTotal(RequestMethod.GET, FIND, serviceOperation, NF_SCREENING);
				}catch(Exception e) {
				commonNrfMetrics.pegNrfDbMetricsFailuresTotal(RequestMethod.GET, FIND, serviceOperation, e, NF_SCREENING);
				}
			} else {
				if(nfScreeningRulesListType != null) {
					if(nfScreeningRulesListStatus != null) {
						try {
						nfScreeningList.add(nfScreeningRepository.findByRecordOwnerAndNfScreeningRulesListTypeAndNfScreeningRulesListStatus(this.nrfConfig.getGlobalConfig().getNrfInstanceId(), nfScreeningRulesListType, nfScreeningRulesListStatus));
						commonNrfMetrics.pegNrfDbMetricsSuccessTotal(RequestMethod.GET, FIND, serviceOperation, NF_SCREENING);
						}catch(Exception e) {
							commonNrfMetrics.pegNrfDbMetricsFailuresTotal(RequestMethod.GET, FIND, serviceOperation, e, NF_SCREENING);
						}
					} else {
						try {
						nfScreeningList.add(nfScreeningRepository.findByRecordOwnerAndNfScreeningRulesListType(this.nrfConfig.getGlobalConfig().getNrfInstanceId(),nfScreeningRulesListType));
						commonNrfMetrics.pegNrfDbMetricsSuccessTotal(RequestMethod.GET, FIND, serviceOperation, NF_SCREENING);
						}catch(Exception e) {
							commonNrfMetrics.pegNrfDbMetricsFailuresTotal(RequestMethod.GET, FIND, serviceOperation, e, NF_SCREENING);
						}
						
						}
				} else {
					try {
					nfScreeningList = nfScreeningRepository.findByRecordOwnerAndNfScreeningRulesListStatus(this.nrfConfig.getGlobalConfig().getNrfInstanceId(),nfScreeningRulesListStatus);
					commonNrfMetrics.pegNrfDbMetricsSuccessTotal(RequestMethod.GET, FIND, serviceOperation, NF_SCREENING);
					}catch(Exception e) {
						commonNrfMetrics.pegNrfDbMetricsFailuresTotal(RequestMethod.GET, FIND, serviceOperation, e, NF_SCREENING);
					}
				}
			}
		} 
		catch(Exception e) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not fetch NfScreeningRules due to a certain db operation error.");
			logMsg.clear();
			logMsg.put("logMsg", e.getMessage());
			logMsg.put("problemDetails",Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
			return prob;
		}
		

		for(NfScreening nfScreening : nfScreeningList) {
			try {
				NfScreeningRules nfScreeningRulesAdditionalAttributes = nfScreening != null ? (NfScreeningRules) nfScreening.toDomain(VERSION) : null;
				NfScreeningRules nfScreeningRules = nfScreening != null ? (NfScreeningRules) nfScreening.toDomain(VERSION) : null;
				nfScreeningRulesListWithAdditionalAttributes.add(nfScreeningRulesAdditionalAttributes);
				if (nfScreeningRules != null) {
					// setting additional attributes as null
					nfScreeningRules.setAdditionalAttributes(null);
				}
				nfScreeningRulesList.add(nfScreeningRules);
			} 
			catch (Exception e) {
				ProblemDetails prob = ProblemDetails.forInternalError();
				prob.setCause("Could not fetch NfScreeningRules due to an unexpected error.");
				logMsg.clear();
				logMsg.put("logMsg", e.getMessage());
				logMsg.put("problemDetails",Arrays.toString(e.getStackTrace()));
				logger.error(logMsg.toString());
				return prob;
			}
		}
		screeningRulesResult.setNfScreeningRulesList(nfScreeningRulesListWithAdditionalAttributes);
		logMsg.clear();
		logMsg.put("logMsg", "Get all NfScreening Rules");
		logMsg.put("screeningRulesResult",screeningRulesResult);
		logger.warn(logMsg.toString());
		screeningRulesResult.setNfScreeningRulesList(nfScreeningRulesList);
		return screeningRulesResult;

	}
	@Override
	public Object updateNfScreeningRulesList(NfScreeningRulesList body) {
		metricsDimension.setMethod(RequestMethod.POST);
		ScreeningRulesResult screeningRulesResult = new ScreeningRulesResult();
		List<NfScreeningRules> nfScreeningRulesList = body.getNfScreeningRulesList();
		Map<String, Object> logMsg = new LinkedHashMap<String, Object>();
		NfScreening nfScreening, savedNfScreeningRules=null;
		Date date = new Date();
		if(nfScreeningRulesList.isEmpty() || nfScreeningRulesList.size()==0) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not update NfScreeningRules due to an unexpected error.");
			return prob;
		}else {
			try {
				for(NfScreeningRules nfScreeningRules : nfScreeningRulesList) {
					nfScreening = new NfScreening(nfScreeningRules,this.nrfConfig.getGlobalConfig().getNrfInstanceId());
					nfScreening.setLastUpdateTimestamp(date);
					metricsDimension.setDbOperation("create");
					try {
					savedNfScreeningRules = nfScreeningRepository.saveAndFlush(nfScreening);
					}catch(Exception e) {
						commonNrfMetrics.pegNrfDbMetricsFailuresTotal(RequestMethod.POST, CREATE, serviceOperation, e, NF_SCREENING);
					}
					if(savedNfScreeningRules != null) {
						commonNrfMetrics.pegNrfDbMetricsSuccessTotal(RequestMethod.POST, CREATE, serviceOperation, NF_SCREENING);
						logMsg.clear();
						logMsg.put("logMsg", "Successfully saved NfScreeningRules");
						logMsg.put("savedNfScreeningRules",savedNfScreeningRules);
						logger.info(logMsg.toString());
					}
					else {
						ProblemDetails prob = ProblemDetails.forInternalError();
						prob.setCause("Could not update NfScreeningRules");
						logMsg.clear();
						logMsg.put("logMsg", "NfScreeningRules updation failed");
						logger.error(logMsg.toString());
						return prob;
					}
				}
			}
			catch (Exception e) {
				ProblemDetails prob = ProblemDetails.forInternalError();
				prob.setCause("Could not update NfScreeningRules due to an unexpected error.");
				logMsg.clear();
				logMsg.put("logMsg", e.getMessage());
				logMsg.put("problemDetails",Arrays.toString(e.getStackTrace()));
				logger.error(logMsg.toString());
				return prob;
			}
		}
		screeningRulesResult.setNfScreeningRulesList(nfScreeningRulesList);
		logMsg.clear();
		logMsg.put("logMsg", "successfully updated BulkNfScreeningRules");
		logMsg.put("screeningRulesResult",screeningRulesResult);
		logger.warn(logMsg.toString());
		return nfScreeningRulesList;
	}

	@Override
	public Object getNfScreeningRule(NfScreeningRulesListType ruleListType) {
		metricsDimension.setMethod(RequestMethod.GET);
		Map<String, Object> logMsg = new LinkedHashMap<String, Object>();
		logMsg.clear();
		logMsg.put("logMsg", "getNfScreeningRule called");
		logger.info(logMsg.toString());
		NfScreening nfScreening = null;
		try {
			nfScreening = nfScreeningRepository.findByRecordOwnerAndNfScreeningRulesListType(this.nrfConfig.getGlobalConfig().getNrfInstanceId(),ruleListType);
			commonNrfMetrics.pegNrfDbMetricsSuccessTotal(RequestMethod.GET,FIND, serviceOperation, NF_SCREENING);
		}
		catch(Exception e) {
			commonNrfMetrics.pegNrfDbMetricsFailuresTotal(RequestMethod.GET,FIND, serviceOperation, e, NF_SCREENING);
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not fetch NfScreeningRule due to a certain db operation error.");
			logMsg.clear();
			logMsg.put("logMsg", e.getMessage());
			logMsg.put("problemDetails",Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
			return prob;
		}
		if(nfScreening == null) {
			ProblemDetails prob = ProblemDetails.forBadRequest();
			prob.setCause("Invalid NfScreening Rule Type '"+ruleListType+"'");
			logMsg.clear();
			logMsg.put("logMsg", "Invalid NfScreening Rule Type");
			logMsg.put("ruleListType",ruleListType);
			logger.error(logMsg.toString());
			return prob;
		}
		try {
			NfScreeningRules nfScreeningRules = (NfScreeningRules) nfScreening.toDomain(VERSION);
			logMsg.clear();
			logMsg.put("logMsg","Get NfScreeningRule");
			logMsg.put("ruleListType",ruleListType);
			logMsg.put("nfScreeningRules",nfScreeningRules);
			logger.warn(logMsg.toString());
			//setting additional attributes as null for operator
			nfScreeningRules.setAdditionalAttributes(null);
			return nfScreeningRules;
		} 
		catch (Exception e) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not fetch NfScreeningRule due to an unexpected error.");
			logMsg.clear();
			logMsg.put("logMsg", e.getMessage());
			logMsg.put("problemDetails",Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
			return prob;
		}
	}

	@Override
	public Object getNrfSystemOptions() {
		metricsDimension.setMethod(RequestMethod.GET);
		NrfSystemOptionsDao nrfSystemOptionsDao;
		NrfSystemOptionsDao nrfSystemOptionsDaoErrorResponses;
		String version = "v1";
		Map<String, Object> logMsg = new LinkedHashMap<String, Object>();
		NrfSystemOptions nrfSystemOptions = null;
		NrfSystemOptions nrfSystemOptionsErrorResponses = null;
		try {

			nrfSystemOptionsDao = nrfSystemOptionsRepository
					.getOcnrfSystemOptions(this.nrfConfig.getGlobalConfig().getNrfInstanceId());
			commonNrfMetrics.pegNrfDbMetricsSuccessTotal(RequestMethod.GET, FIND, serviceOperation, NRF_SYSTEMOPTIONS);

		} catch (Exception e) {
			commonNrfMetrics.pegNrfDbMetricsFailuresTotal(RequestMethod.GET, FIND, serviceOperation, e,
					NRF_SYSTEMOPTIONS);
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not fetch NrfConfiguration due to an unexpected error.");
			logMsg.clear();
			logMsg.put("logMsg", e.getMessage());
			logMsg.put("problemDetails",Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
			return prob;
		}
		try {

			nrfSystemOptionsDaoErrorResponses = nrfSystemOptionsRepository
					.getOcnrfErrorResponses(this.nrfConfig.getGlobalConfig().getNrfInstanceId());
			commonNrfMetrics.pegNrfDbMetricsSuccessTotal(RequestMethod.GET, FIND, serviceOperation, NRF_SYSTEMOPTIONS);
		} catch (Exception e) {
			commonNrfMetrics.pegNrfDbMetricsFailuresTotal(RequestMethod.GET, FIND, serviceOperation, e,
					NRF_SYSTEMOPTIONS);
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not fetch NrfConfiguration due to an unexpected error.");
			logMsg.clear();
			logMsg.put("logMsg", e.getMessage());
			logMsg.put("problemDetails",Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
			return prob;
		}
		if (nrfSystemOptionsDao == null) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not fetch NrfSystemOptions due to an unexpected error.");
			prob.setDetail("Unable to fetch NrfSystemOptions with ID:OCNRF_SYSTEM_OPTIONS");
			logMsg.clear();
			logMsg.put("logMsg",
					"getNrfSystemOptions failed. Unable to fetch nrfSystemOptions with ID:OCNRF_SYSTEM_OPTIONS");
			logger.error(logMsg.toString());
			return prob;
		}
		if (nrfSystemOptionsDaoErrorResponses == null) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not fetch NrfSystemOptions due to an unexpected error.");
			prob.setDetail("Unable to fetch NrfSystemOptions with ID:OCNRF_ERROR_RESPONSES");
			logMsg.clear();
			logMsg.put("logMsg",
					"getNrfSystemOptions failed. Unable to fetch nrfSystemOptions with ID:OCNRF_ERROR_RESPONSES");
			logger.error(logMsg.toString());
			return prob;
		}

		logMsg.clear();
		logMsg.put("logMsg", "Existing values of NrfSystemOptions");
		logMsg.put("nrfSystemOptionsDao", nrfSystemOptionsDao);
		logger.info(logMsg.toString());
		try {

			nrfSystemOptions = (NrfSystemOptions) nrfSystemOptionsDao.toDomain(version);
			nrfSystemOptionsErrorResponses = (NrfSystemOptions) nrfSystemOptionsDaoErrorResponses.toDomain(version);
			ErrorResponses errorResponse = new ErrorResponses();
			errorResponse = nrfSystemOptionsErrorResponses.getErrorResponses();
			List<ErrorInfo> errorInfoList = errorResponse.getSlfErrorResponses();
			for (ErrorInfo errorInfo : errorInfoList) {
				errorInfo.setErrorDetectionResultCode(null);
				errorInfo.setUseErrorCodeReturned(null);
			}
			nrfSystemOptions.setErrorResponses(errorResponse);

			logMsg.clear();
			logMsg.put("logMsg", "Get Nrf System Options");
			logMsg.put("nrfSystemOptions",nrfSystemOptions);
			logger.warn(logMsg.toString());

			
			List<ErrorInfo> forwardingErrorInfoList = errorResponse.getNrfForwardingErrorResponses();
			for (ErrorInfo errorInfo : forwardingErrorInfoList) {
				errorInfo.setErrorDetectionResultCode(null);
				errorInfo.setUseErrorCodeReturned(null);
			}
			nrfSystemOptions.setErrorResponses(errorResponse);

			NfDiscoverSystemOptions nfDiscoverSystemOptions = nrfSystemOptions.getNfDiscoverSystemOptions();
			if (nfDiscoverSystemOptions.getDiscoveryResultLoadThreshold() == null) {
				nfDiscoverSystemOptions.setDiscoveryResultLoadThreshold(0);
			}
			if (nfDiscoverSystemOptions.getProfilesCountInDiscoveryResponse() == null) {
				nfDiscoverSystemOptions.setProfilesCountInDiscoveryResponse(0);
			}
			nrfSystemOptions.setNfDiscoverSystemOptions(nfDiscoverSystemOptions);
			//setting additional attributes as null for operator
			nrfSystemOptions.setAdditionalAttributes(null);
		} catch (Exception e) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			logMsg.clear();
			logMsg.put("logMsg", "An exception occured");
			logMsg.put("stackTrace", e.toString());
			logger.error(logMsg.toString());
			return prob;
		}
		return nrfSystemOptions;
	}

	@Override
	public Object getNrfEngSystemOptions() {
		metricsDimension.setMethod(RequestMethod.GET);
		NrfSystemOptionsDao nrfEngSystemOptionsDao;
		NrfSystemOptionsDao nrfEngSystemOptionsErrorResponsesDao;
		String version = "v1";
		Map<String, Object> logMsg = new LinkedHashMap<String, Object>();
		NrfEngSystemOptions nrfEngSystemOptions = null;
		NrfEngSystemOptions nrfEngSystemOptionsErrorResponses = null;

		try {

			nrfEngSystemOptionsErrorResponsesDao = nrfSystemOptionsRepository
					.getOcnrfEngErrorResponse(this.nrfConfig.getGlobalConfig().getNrfInstanceId());
			nrfEngSystemOptionsDao = nrfSystemOptionsRepository
					.getOcnrfEngSystemOptions(this.nrfConfig.getGlobalConfig().getNrfInstanceId());
			commonNrfMetrics.pegNrfDbMetricsSuccessTotal(RequestMethod.GET, FIND, serviceOperation, NRF_SYSTEMOPTIONS);

		} catch (Exception e) {
			commonNrfMetrics.pegNrfDbMetricsFailuresTotal(RequestMethod.GET, FIND, serviceOperation, e,
					NRF_SYSTEMOPTIONS);
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not fetch NrfEngConfiguration due to an unexpected error.");
			logMsg.clear();
			logMsg.put("logMsg", e.getMessage());
			logMsg.put("problemDetails",Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
			return prob;
		}
		if (nrfEngSystemOptionsErrorResponsesDao == null) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not fetch NrfEngSystemOptions due to an unexpected error.");
			prob.setDetail("Unable to fetch NrfEngSystemOptions with ID:OCNRF_ENG_ERROR_RESPONSES");
			logMsg.clear();
			logMsg.put("logMsg",
					"getNrfEngSystemOptions failed. Unable to fetch nrfEngSystemOptions with ID:OCNRF_ENG_ERROR_RESPONSES");
			logger.error(logMsg.toString());
			return prob;
		}
		if (nrfEngSystemOptionsDao == null) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not fetch NrfEngSystemOptions due to an unexpected error.");
			prob.setDetail("Unable to fetch NrfEngSystemOptions with ID:OCNRF_ENG_SYSTEM_OPTIONS");
			logMsg.clear();
			logMsg.put("logMsg",
					"getNrfEngSystemOptions failed. Unable to fetch nrfEngSystemOptions with ID:OCNRF_ENG_ERROR_RESPONSES");
			logger.error(logMsg.toString());
			return prob;
		}
		logMsg.clear();
		logMsg.put("logMsg", "Existing values of NrfEngSystemOptions");
		logMsg.put("nrfEngSystemOptionsDao", nrfEngSystemOptionsDao);
		logger.info(logMsg.toString());
		try {
			nrfEngSystemOptions = (NrfEngSystemOptions) nrfEngSystemOptionsDao.toDomain_NrfEngSystemOptions(version);
			nrfEngSystemOptionsErrorResponses = (NrfEngSystemOptions) nrfEngSystemOptionsErrorResponsesDao
					.toDomain_NrfEngSystemOptions(version);

			ErrorResponses errorResponse = new ErrorResponses();
			errorResponse = nrfEngSystemOptionsErrorResponses.getErrorResponses();
			List<ErrorInfo> errorInfoList = errorResponse.getSlfErrorResponses();
			for (ErrorInfo errorInfo : errorInfoList) {
				errorInfo.setErrorDetectionResultCode(null);
				errorInfo.setUseErrorCodeReturned(null);
			}
			nrfEngSystemOptions.setErrorResponses(errorResponse);
			logMsg.clear();
			logMsg.put("logMsg", "Get Nrf Engineering System Options");
			logMsg.put("nrfSystemOptions",nrfEngSystemOptions);
			logger.warn(logMsg.toString());
			
			//setting additional attributes as null for operator
			nrfEngSystemOptions.setAdditionalAttributes(null);
			
		} catch (Exception e) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			logMsg.clear();
			logMsg.put("logMsg", "An exception occured");
			logMsg.put("stackTrace", e.toString());
			logger.error(logMsg.toString());
			return prob;
		}
		return nrfEngSystemOptions;
	}
	
	@Override
	public Object updateNrfSystemOptions(NrfSystemOptions nrfSystemOptions) {
		NrfSystemOptionsDao oldNrfSystemOptionsDao;
		String version = "v1";
		NrfSystemOptionsDao oldNrfSystemOptionsDaoErrorResponses;
		Map<String, Object> logMsg = new LinkedHashMap<String, Object>();
		metricsDimension.setMethod(RequestMethod.PUT);
		try {

			oldNrfSystemOptionsDao = nrfSystemOptionsRepository
					.getOcnrfSystemOptions(this.nrfConfig.getGlobalConfig().getNrfInstanceId());
			commonNrfMetrics.pegNrfDbMetricsSuccessTotal(RequestMethod.PUT, FIND, serviceOperation, NRF_SYSTEMOPTIONS);
		} catch (Exception e) {
			commonNrfMetrics.pegNrfDbMetricsFailuresTotal(RequestMethod.PUT, FIND, serviceOperation, e,
					NRF_SYSTEMOPTIONS);
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not update NrfConfiguration due to an unexpected error.");
			logMsg.clear();
			logMsg.put("logMsg", e.getMessage());
			logMsg.put("problemDetails",Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
			throw new NrfException(prob);
		}
		try {

			oldNrfSystemOptionsDaoErrorResponses = nrfSystemOptionsRepository
					.getOcnrfErrorResponses(this.nrfConfig.getGlobalConfig().getNrfInstanceId());
			commonNrfMetrics.pegNrfDbMetricsSuccessTotal(RequestMethod.PUT, FIND, serviceOperation, NRF_SYSTEMOPTIONS);
		} catch (Exception e) {
			commonNrfMetrics.pegNrfDbMetricsFailuresTotal(RequestMethod.PUT, FIND, serviceOperation, e,
					NRF_SYSTEMOPTIONS);
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not update NrfConfiguration due to an unexpected error.");
			logMsg.clear();
			logMsg.put("logMsg", e.getMessage());
			logMsg.put("problemDetails", Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
			throw new NrfException(prob);
		}
		if (oldNrfSystemOptionsDao == null) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not update NrfSystemOptions due to an unexpected error.");
			prob.setDetail("Unable to fetch NrfSystemOptions with ID:OCNRF_SYSTEM_OPTIONS");
			logMsg.clear();
			logMsg.put("logMsg",
					"getNrfSystemOptions failed. Unable to fetch nrfSystemOptions with ID:OCNRF_SYSTEM_OPTIONS");
			logger.error(logMsg.toString());
			throw new NrfException(prob);

		}
		if (oldNrfSystemOptionsDaoErrorResponses == null) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not update NrfSystemOptions due to an unexpected error.");
			prob.setDetail("Unable to fetch NrfSystemOptions with ID:OCNRF_ERROR_RESPONSES");
			logMsg.clear();
			logMsg.put("logMsg",
					"getNrfSystemOptions failed. Unable to fetch nrfSystemOptions with ID:OCNRF_SYSTEM_OPTIONS");
			logger.error(logMsg.toString());
			throw new NrfException(prob);

		}

		// validate ForwardingSystemOptions
		try {
			validateForwardingConfig(nrfSystemOptions, (NrfSystemOptions) oldNrfSystemOptionsDao.toDomain(version));
		} catch (NrfException e) {
			ProblemDetails prob = e.getProbDetails();
			logMsg.clear();
			logMsg.put("logMsg", e.getProbDetails());
			logger.error(logMsg.toString());
			throw new NrfException(prob);
		}

		// validate SlfSystemOptions
		try {
			validateSlfSystemOptionsConfig(nrfSystemOptions,
					(NrfSystemOptions) oldNrfSystemOptionsDao.toDomain(version));
		} catch (NrfException e) {
			ProblemDetails prob = e.getProbDetails();
			logMsg.clear();
			logMsg.put("logMsg", e.getProbDetails());
			logger.error(logMsg.toString());
			throw new NrfException(prob);
		}
		

		//Validate nfAuthenticationErrorResponse
		try {
			validateNfAuthenticationErrorResponses(nrfSystemOptions, (NrfSystemOptions) oldNrfSystemOptionsDao.toDomain(version));			
		} catch(NrfException e) {
			ProblemDetails prob = e.getProbDetails();
			logMsg.clear();
			logMsg.put("logMsg", e.getProbDetails());
			logger.error(logMsg.toString());
			throw new NrfException(prob);
		}

		//validate authFeatureConfig
		try {
			validateAuthFeatureConfig(nrfSystemOptions,
					(NrfSystemOptions) oldNrfSystemOptionsDao.toDomain(version));
		} catch (NrfException e) {
			ProblemDetails prob = e.getProbDetails();
			logMsg.clear();
			logMsg.put("logMsg", e.getProbDetails());
			logger.error(logMsg.toString());
			throw new NrfException(prob);
		}

		NrfSystemOptionsDao nrfSystemOptionsDao = new NrfSystemOptionsDao(oldNrfSystemOptionsDao, nrfSystemOptions,
				version);
		NrfSystemOptionsDao nrfSystemOptionsDaoErrorResponses = new NrfSystemOptionsDao(
				oldNrfSystemOptionsDaoErrorResponses, nrfSystemOptions, version);

		metricsDimension.setDbOperation("update");
		try {
			nrfSystemOptionsDao = nrfSystemOptionsRepository.save(nrfSystemOptionsDao);
			commonNrfMetrics.pegNrfDbMetricsSuccessTotal(RequestMethod.PUT, UPDATE, serviceOperation,
					NRF_SYSTEMOPTIONS);
		} catch (Exception e) {
			commonNrfMetrics.pegNrfDbMetricsFailuresTotal(RequestMethod.PUT, UPDATE, serviceOperation, e,
					NRF_SYSTEMOPTIONS);
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not update NrfConfiguration due to an unexpected error.");
			logMsg.clear();
			logMsg.put("logMsg", e.getMessage());
			logMsg.put("problemDetails",Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
			throw new NrfException(prob);
		}
		try {
			nrfSystemOptionsDaoErrorResponses = nrfSystemOptionsRepository.save(nrfSystemOptionsDaoErrorResponses);
			commonNrfMetrics.pegNrfDbMetricsSuccessTotal(RequestMethod.PUT, UPDATE, serviceOperation,
					NRF_SYSTEMOPTIONS);
		} catch (Exception e) {
			commonNrfMetrics.pegNrfDbMetricsFailuresTotal(RequestMethod.PUT, UPDATE, serviceOperation, e,
					NRF_SYSTEMOPTIONS);
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not update NrfConfiguration due to an unexpected error.");
			logMsg.clear();
			logMsg.put("logMsg", e.getMessage());
			logMsg.put("problemDetails",Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
			throw new NrfException(prob);
		}
		if (nrfSystemOptionsDao == null) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not update NrfSystemOptions due to an unexpected error.");
			prob.setDetail("Save failed for NrfSystemOptions with ID:OCNRF_SYSTEM_OPTIONS");
			logMsg.clear();
			logMsg.put("logMsg",
					"updateNrfSystemOptions failed due to an unexpected error.Save failed for NrfSystemOptions with ID:OCNRF_SYSTEM_OPTIONS");
			logger.error(logMsg.toString());
			throw new NrfException(prob);
		}
		if (nrfSystemOptionsDaoErrorResponses == null) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not update NrfSystemOptions due to an unexpected error.");
			prob.setDetail("Save failed for NrfSystemOptions with ID:OCNRF_ERROR_RESPONSES");
			logMsg.clear();
			logMsg.put("logMsg",
					"updateNrfSystemOptions failed due to an unexpected error.Save failed for NrfSystemOptions with ID:OCNRF_ERROR_RESPONSES");
			logger.error(logMsg.toString());
			throw new NrfException(prob);
		}
		logMsg.clear();
		logMsg.put("logMsg", "NrfSystemOptions updated with nrfSystemOptionsDao");
		logMsg.put("nrfSystemOptionsDao", nrfSystemOptionsDao);
		logger.info(logMsg.toString());
		NrfSystemOptions nrfSystemOptionsResponse = null;
		NrfSystemOptions nrfSystemOptionsErrorResponses = null;
		try {
			nrfSystemOptionsResponse = (NrfSystemOptions) nrfSystemOptionsDao.toDomain(version);
			nrfSystemOptionsErrorResponses = (NrfSystemOptions) nrfSystemOptionsDaoErrorResponses.toDomain(version);

		} catch (Exception e) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			logMsg.clear();
			logMsg.put("logMsg", "An exception occured");
			logMsg.put("stackTrace", e.toString());
			logger.error(logMsg.toString());
			return prob;
		}
		// Fetching the latest log level
		if(nrfSystemOptions.getLoggingLevelSystemOptions().getNrfConfigurationLogLevel()!=null) {
		if(!(nrfSystemOptions.getLoggingLevelSystemOptions().getNrfConfigurationLogLevel().equals(LogManager.getRootLogger().getLevel().toString())))
		{
			Configurator.setAllLevels(LogManager.getRootLogger().getName(),Level.toLevel(nrfSystemOptions.getLoggingLevelSystemOptions().getNrfConfigurationLogLevel()));
		}
		}

		ErrorResponses errorResponse = new ErrorResponses();
		errorResponse = nrfSystemOptionsErrorResponses.getErrorResponses();
		List<ErrorInfo> errorInfoList = errorResponse.getSlfErrorResponses();
		for (ErrorInfo errorInfo : errorInfoList) {
			errorInfo.setErrorDetectionResultCode(null);
			errorInfo.setUseErrorCodeReturned(null);
		}
		nrfSystemOptionsResponse.setErrorResponses(errorResponse);

		logMsg.clear();
		logMsg.put("logMsg", "Updated NrfSystemOptions with request received");
		logMsg.put("nrfSystemOptions", nrfSystemOptionsResponse);
		logger.warn(logMsg.toString());
		
		List<ErrorInfo> forwardingErrorInfoList = errorResponse.getNrfForwardingErrorResponses();
		for (ErrorInfo errorInfo : forwardingErrorInfoList) {
			errorInfo.setErrorDetectionResultCode(null);
			errorInfo.setUseErrorCodeReturned(null);
		}
		nrfSystemOptionsResponse.setErrorResponses(errorResponse);

		NfDiscoverSystemOptions nfDiscoverSystemOptions = nrfSystemOptionsResponse.getNfDiscoverSystemOptions();
		if (nfDiscoverSystemOptions.getDiscoveryResultLoadThreshold() == null) {
			nfDiscoverSystemOptions.setDiscoveryResultLoadThreshold(0);
		}
		if (nfDiscoverSystemOptions.getProfilesCountInDiscoveryResponse() == null) {
			nfDiscoverSystemOptions.setProfilesCountInDiscoveryResponse(0);
		}
		nrfSystemOptionsResponse.setNfDiscoverSystemOptions(nfDiscoverSystemOptions);
		//setting additional attributes as null for operator
		nrfSystemOptionsResponse.setAdditionalAttributes(null);
		return nrfSystemOptionsResponse;

	}

	@Override
	public Object updateNrfEngSystemOptions(NrfEngSystemOptions nrfEngSystemOptions) {
		NrfSystemOptionsDao nrfEngSystemOptionsDaoOld;
		NrfSystemOptionsDao nrfEngSystemErrorResponsesDaoOld;
		String version = "v1";
		Map<String, Object> logMsg = new LinkedHashMap<String, Object>();
		metricsDimension.setMethod(RequestMethod.PUT);
		try {

			nrfEngSystemErrorResponsesDaoOld = nrfSystemOptionsRepository
					.getOcnrfEngErrorResponse(this.nrfConfig.getGlobalConfig().getNrfInstanceId());
			nrfEngSystemOptionsDaoOld = nrfSystemOptionsRepository
					.getOcnrfEngSystemOptions(this.nrfConfig.getGlobalConfig().getNrfInstanceId());
			commonNrfMetrics.pegNrfDbMetricsSuccessTotal(RequestMethod.PUT, FIND, serviceOperation, NRF_SYSTEMOPTIONS);

		} catch (Exception e) {
			commonNrfMetrics.pegNrfDbMetricsFailuresTotal(RequestMethod.PUT, FIND, serviceOperation, e,
					NRF_SYSTEMOPTIONS);
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not update NrfEngConfiguration due to an unexpected error.");
			logMsg.clear();
			logMsg.put("logMsg", e.getMessage());
			logMsg.put("problemDetails",Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
			throw new NrfException(prob);
		}
		if (nrfEngSystemErrorResponsesDaoOld == null) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not update NrfEngSystemOptions due to an unexpected error.");
			prob.setDetail("Unable to fetch NrfEngSystemOptions with ID:OCNRF_ENG_ERROR_RESPONSES");
			logMsg.clear();
			logMsg.put("logMsg",
					"getNrfEngSystemOptions failed. Unable to fetch nrfEngSystemOptions with ID:OCNRF_ENG_ERROR_RESPONSES");
			logger.error(logMsg.toString());
			throw new NrfException(prob);

		}
		if (nrfEngSystemOptionsDaoOld == null) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not update NrfEngSystemOptions due to an unexpected error.");
			prob.setDetail("Unable to fetch NrfEngSystemOptions with ID:OCNRF_ENG_SYSTEM_OPTIONS");
			logMsg.clear();
			logMsg.put("logMsg",
					"getNrfEngSystemOptions failed. Unable to fetch nrfEngSystemOptions with ID:OCNRF_ENG_ERROR_RESPONSES");
			logger.error(logMsg.toString());
			throw new NrfException(prob);

		}
		NrfSystemOptionsDao nrfEngSystemOptionsErrorResponsesDao = new NrfSystemOptionsDao(
				nrfEngSystemErrorResponsesDaoOld, nrfEngSystemOptions, version);
		NrfSystemOptionsDao nrfEngSystemOptionsDao = new NrfSystemOptionsDao(nrfEngSystemOptionsDaoOld,
				nrfEngSystemOptions, version);
		metricsDimension.setDbOperation("update");
		try {

			nrfEngSystemOptionsDao = nrfSystemOptionsRepository.save(nrfEngSystemOptionsDao);

			nrfEngSystemOptionsErrorResponsesDao = nrfSystemOptionsRepository
					.save(nrfEngSystemOptionsErrorResponsesDao);

			/*
			 * commonNrfMetrics.pegNrfDbMetricsSuccessTotal(RequestMethod.PUT, UPDATE,
			 * serviceOperation, NRF_SYSTEMOPTIONS);
			 */

		} catch (Exception e) {
			commonNrfMetrics.pegNrfDbMetricsFailuresTotal(RequestMethod.PUT, UPDATE, serviceOperation, e,
					NRF_SYSTEMOPTIONS);
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not update NrfEngConfiguration due to an unexpected error.");
			logMsg.clear();
			logMsg.put("logMsg", e.getMessage());
			logMsg.put("problemDetails",Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
			throw new NrfException(prob);
		}

		if (nrfEngSystemOptionsDao == null) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not update NrfEngSystemOptions due to an unexpected error.");
			prob.setDetail("Save failed for NrfEngSystemOptions with ID:OCNRF_ENG_ERROR_RESPONSES");
			logMsg.clear();
			logMsg.put("logMsg",
					"updateNrfEngSystemOptions failed due to an unexpected error.Save failed for NrfEngSystemOptions with ID:OCNRF_ENG_ERROR_RESPONSES");
			logger.error(logMsg.toString());
			throw new NrfException(prob);
		}
		logMsg.clear();
		logMsg.put("logMsg", "NrfEngSystemOptions updated with nrfEngSystemOptionsDao");
		logMsg.put("nrfEngSystemOptionsDao", nrfEngSystemOptionsDao);
		logger.info(logMsg.toString());
		NrfEngSystemOptions nrfEngSystemOptionsResponse = null;
		NrfEngSystemOptions nrfEngSystemOptionsErrorResponses = null;
		try {
			nrfEngSystemOptionsResponse = (NrfEngSystemOptions) nrfEngSystemOptionsDao
					.toDomain_NrfEngSystemOptions(version);

			nrfEngSystemOptionsErrorResponses = (NrfEngSystemOptions) nrfEngSystemOptionsErrorResponsesDao
					.toDomain_NrfEngSystemOptions(version);

		} catch (Exception e) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			logMsg.clear();
			logMsg.put("logMsg", "An exception occured");
			logMsg.put("stackTrace", e.toString());
			logger.error(logMsg.toString());
			return prob;
		}

		ErrorResponses errorResponse = new ErrorResponses();
		errorResponse = nrfEngSystemOptionsErrorResponses.getErrorResponses();
		List<ErrorInfo> errorInfoList = errorResponse.getSlfErrorResponses();
		for (ErrorInfo errorInfo : errorInfoList) {
			errorInfo.setErrorDetectionResultCode(null);
			errorInfo.setUseErrorCodeReturned(null);
		}
		nrfEngSystemOptionsResponse.setErrorResponses(errorResponse);
		logMsg.clear();
		logMsg.put("logMsg", "Updated NrfEngSystemOptions with request received");
		logMsg.put("nrfEngSystemOptions", nrfEngSystemOptionsResponse);
		logger.warn(logMsg.toString());
		
		//setting additional attributes as null for operator
		nrfEngSystemOptionsResponse.setAdditionalAttributes(null);
		return nrfEngSystemOptionsResponse;
	}

	@Override
	public Object getNfProfileEvents(String nfInstanceId) {
		Map<String, Object> logMsg = new LinkedHashMap<String, Object>();
		logMsg.clear();
		logMsg.put("logMsg", "getAllNfProfileEvents() called");
		logMsg.put("nfInstanceId", nfInstanceId);
		logger.info(logMsg.toString());
		String version = "v1";
		List<NrfEventTransactionsDao> eventDetailsList;
		try {
			eventDetailsList = nrfEventTransactionsRepository.findAll();
		}catch(Exception e) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not fetch NrfEventTransactions due to an unexpected error.");
			logMsg.clear();
			logMsg.put("logMsg", e.getMessage());
			logMsg.put("problemDetails",Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
			return prob;
		}
		if (eventDetailsList == null || eventDetailsList.isEmpty()) {
			ProblemDetails prob = ProblemDetails.forNotFound();
			prob.setCause("Could not fetch NrfEventTransactions");
			logMsg.clear();
			logMsg.put("logMsg", "No NrfEventTransactions found");
			logger.error(logMsg.toString());
			return prob;
		}
		NrfEventDetails eventDetails;
		List<NrfEventDetails> nrfEventList = new ArrayList<NrfEventDetails>();
		try {
			for (NrfEventTransactionsDao dao:eventDetailsList) {
				eventDetails = (NrfEventDetails)dao.toDomain(version);
				if (eventDetails.getNfInstanceId()!=null) {
					if(nfInstanceId!=null) {
						//Check for nfProfileEvents matching nfInstanceId specified in query parameter
						if (eventDetails.getNfInstanceId().equals(nfInstanceId))
							nrfEventList.add(eventDetails);
					}
					else {
						//When nfInstanceId not specified, return all nfProfile events
						nrfEventList.add(eventDetails);
					}						
				}					
			}
		}catch(Exception e) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not retrieve NrfEventDetails due to an unexpected error.");
			logMsg.clear();
			logMsg.put("logMsg", e.getMessage());
			logMsg.put("problemDetails",Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
			return prob;
		}
		if (nrfEventList==null || nrfEventList.isEmpty()) {
			ProblemDetails prob = ProblemDetails.forNotFound();
			prob.setCause("Could not find NfProfile events");
			logMsg.clear();
			logMsg.put("logMsg", "No NrfEventTransactions found for nfInstanceId");
			logMsg.put("nfInstanceId", nfInstanceId);
			logger.error(logMsg.toString());
			return prob;
		}
		NrfEventResponse nrfEventResponse = new NrfEventResponse();
		nrfEventResponse.setNrfEventList(nrfEventList);
		return nrfEventResponse;	
	}

	@Override
	public Object getNfSubscriptionEvents(String subscriptionId) {
		Map<String, Object> logMsg = new LinkedHashMap<String, Object>();
		logMsg.clear();
		logMsg.put("logMsg", "getNfSubscriptionEvents() called");
		logMsg.put("subscriptionId",subscriptionId);
		logger.info(logMsg.toString());
		String version = "v1";
		List<NrfEventTransactionsDao> eventDetailsList;
		try {
			eventDetailsList = nrfEventTransactionsRepository.findAll();
		}catch(Exception e) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not fetch NrfEventTransactions due to an unexpected error.");
			logMsg.clear();
			logMsg.put("logMsg", e.getMessage());
			logMsg.put("problemDetails",Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
			return prob;
		}
		if (eventDetailsList == null || eventDetailsList.isEmpty()) {
			ProblemDetails prob = ProblemDetails.forNotFound();
			prob.setCause("Could not fetch NrfEventTransactions");
			logMsg.clear();
			logMsg.put("logMsg", "No NrfEventTransactions found");
			logger.error(logMsg.toString());
			return prob;
		}
		NrfEventDetails eventDetails;
		List<NrfEventDetails> nrfEventList = new ArrayList<NrfEventDetails>();
		try {
			for (NrfEventTransactionsDao dao:eventDetailsList) {
				eventDetails = (NrfEventDetails)dao.toDomain(version);
				if (eventDetails.getSubscriptionId()!=null) {
					if(subscriptionId!=null) {
						//Check for nfSubscriptionEvents matching subscriptionId specified in query parameter
						if (eventDetails.getSubscriptionId().equals(subscriptionId))
							nrfEventList.add(eventDetails);
					}
					else {
						//When subscriptionId not specified, return all nfSubscription events
						nrfEventList.add(eventDetails);
					}						
				}				
			}
		}catch(Exception e) {
			ProblemDetails prob = ProblemDetails.forInternalError();
			prob.setCause("Could not retrieve NrfEventDetails due to an unexpected error.");
			logMsg.clear();
			logMsg.put("logMsg", e.getMessage());
			logMsg.put("problemDetails",Arrays.toString(e.getStackTrace()));
			logger.error(logMsg.toString());
			return prob;
		}
		if (nrfEventList==null || nrfEventList.isEmpty()) {
			ProblemDetails prob = ProblemDetails.forNotFound();
			prob.setCause("Could not find NfSubscription events");
			logMsg.clear();
			logMsg.put("logMsg", "No NrfEventTransactions found for subscriptionId");
			logMsg.put(subscriptionId,"subscriptionId");
			logger.error(logMsg.toString());
			return prob;
		}
		NrfEventResponse nrfEventResponse = new NrfEventResponse();
		nrfEventResponse.setNrfEventList(nrfEventList);
		return nrfEventResponse;
	}
	
	public Object updateNfScreeningRule(NfScreeningRulesListType ruleListType, List<PatchItem> patchItem) {
		Map<String, Object> logMsg = new LinkedHashMap<String, Object>();
		logMsg.clear();
		logMsg.put("logMsg", "updateNfScreeningRule()");
		logger.info(logMsg.toString());
		ProblemDetails problem = ProblemDetails.forInternalError();
		NfScreening nfScreening;
		boolean isValid = true;
		metricsDimension.setMethod(RequestMethod.PATCH);
		
		// Get the Rule from the db using the ruleName
		try {
			nfScreening = nfScreeningRepository.findByRecordOwnerAndNfScreeningRulesListType(this.nrfConfig.getGlobalConfig().getNrfInstanceId(),ruleListType);
			commonNrfMetrics.pegNrfDbMetricsSuccessTotal(RequestMethod.PATCH, FIND, serviceOperation, NF_SCREENING);
		} catch (Exception e) {
			commonNrfMetrics.pegNrfDbMetricsFailuresTotal(RequestMethod.PATCH, FIND, serviceOperation, e, NF_SCREENING);
			problem.setCause("Internal Error");
			problem.setDetail(e.getLocalizedMessage());
			return problem;
		}

		// No rules present
		if(nfScreening == null) {
			logMsg.clear();
			logMsg.put("logMsg", "NfScreeningRule for ruleListType is not found");
			logMsg.put("ruleListType", ruleListType);
			logger.error(logMsg.toString());
			problem =  ProblemDetails.forNotFound();
			problem.setCause("NfScreeningRule for " + ruleListType + " is not found");
			problem.setDetail("NfScreeningRule for " + ruleListType + " is not found");
			return problem;
		}
		//logger.info("Rule configured in the db {}", nfScreening);
		// Apply all Patch operation on the nfScreeningRules object
		JsonObject nfRuleConfig = Json.createReader(new StringReader(nfScreening.toDomainDoc(VERSION))).readObject();
		
		List<InvalidParam> invalidParams = new ArrayList<InvalidParam>(); 
		for(PatchItem item : patchItem) {
			Object response = applyPatchOperationOnJson(item, nfRuleConfig);
			if(response instanceof ProblemDetails) {
				logMsg.clear();
				logMsg.put("logMsg", "Patch operation returned error");
				logMsg.put("response", response);
				logger.error(logMsg.toString());
				invalidParams.add(new InvalidParam("patchItem",item.toString()));
				isValid = false;
			} 
			else {	
				try {
					// if it is not valid JSON, exception will get raised
					ObjectMapper om = new ObjectMapper();
					NfScreeningRules rule = om.readValue(response.toString(), NfScreeningRules.class);
					if(isNfScreeningAttributeReadOnly(item.getPath())) {
						throw new Exception(item.getPath()+" is read-only attribute");
					}

					// if it is not semantically valid, exception will be raised
					Validator validator = Validation.buildDefaultValidatorFactory().getValidator();
					if(!validator.validate(rule).isEmpty()) {
						// Uncomment the following code if you need to debug
						//				for(ConstraintViolation<NfScreeningRules> err:validator.validate(rule)) {
						//					System.err.println(err.toString());
						//				}
						throw new Exception("constraint violated");
					}

					try {
						rule.semanticValidation(this.maxCount);
					}catch (NrfException e) {
						logMsg.clear();
						logMsg.put("logMsg", "Patch operation returned error");
						logMsg.put("response", e.getProbDetails());
						logger.error(logMsg.toString());
						ProblemDetails prob = e.getProbDetails();
						return prob;
					} 

				}catch(NrfException e) {
					return(e.getProbDetails());
				}catch(Exception e) {
					problem = ProblemDetails.forUnprocessableRequest();
					problem.setDetail("patch causes the resource to become invalid");
					problem.addInvalidParam(new InvalidParam("patchItem",item.toString()));
					return problem;
				}

				nfRuleConfig = (JsonObject)response;
			}
		}

		if(!isValid) {
			logMsg.clear();
			logMsg.put("ProblemDetails", problem);
			logger.error(logMsg.toString());
			if(invalidParams.size()>1) {
				problem.setDetail("Multiple patchItem errors");
			}
			problem = ProblemDetails.forBadRequest();
			problem.setDetail("Invalid JSON format");
			problem.setInvalidParams(invalidParams);
			return problem;
		}

		// Save the rule in the db
		try {
			NfScreeningRules rules = new ObjectMapper().readValue(nfRuleConfig.toString(), NfScreeningRules.class);
			//constructor for retaining old additional attributes values
			NfScreening updatedRule = new NfScreening(nfScreening, rules);
			NfScreening savedNfScreeningRules=null;
			metricsDimension.setDbOperation("update");
			try {
			 savedNfScreeningRules = nfScreeningRepository.saveAndFlush(updatedRule);
			 commonNrfMetrics.pegNrfDbMetricsSuccessTotal(RequestMethod.PATCH, UPDATE, serviceOperation, NF_SCREENING);
			
			}catch(Exception e) {
				commonNrfMetrics.pegNrfDbMetricsFailuresTotal(RequestMethod.PATCH, UPDATE, serviceOperation, e, NF_SCREENING);
			}
			logMsg.clear();
			logMsg.put("logMsg", "Successfully updated NfScreeningRules");
			logMsg.put("updatedNfScreeningRules",savedNfScreeningRules);
			logger.warn(logMsg.toString());
			//setting additional attributes as null
			rules.setAdditionalAttributes(null);
			return rules;
		}catch (Exception e) {
			problem.setCause("Could not update NfScreeningRules");
			problem.setDetail(e.getMessage());
			logMsg.clear();
			logMsg.put("logMsg", "NfScreeningRules updation failed");
			logger.error(logMsg.toString());
			return problem;
		}
	}

	private Object applyPatchOperationOnJson( PatchItem item, JsonObject jsonObject) {
		ProblemDetails problem = ProblemDetails.forInternalError();
		Object retObj = null;
		switch(item.getOp()) {
		case "add":
			retObj = PatchHelper.applyAddPatch(item, jsonObject);
			if(retObj instanceof ProblemDetails) {
				return retObj;
			}else {
				jsonObject = (JsonObject) retObj;
			}
			break;

		case "copy":
			break;
		case "move":
			break;
		case "remove":
			retObj = PatchHelper.applyRemovePatch(item, jsonObject);
			if(retObj instanceof ProblemDetails) {
				return retObj;
			}else {
				jsonObject = (JsonObject) retObj;
			}
			break;
		case "replace":
			retObj = PatchHelper.applyReplacePatch(item, jsonObject);
			if(retObj instanceof ProblemDetails) {
				return retObj;
			}else {
				jsonObject = (JsonObject) retObj;
			}
			break;
		case "test":
			break;
		default:
			return problem;
		}

		return jsonObject;
	}

	private boolean isNfScreeningAttributeReadOnly(String path) {
		if (path.equals("/nfScreeningRulesListType")) {
			return true;
		}
		return false;
	}

	public void validateForwardingConfig(NrfSystemOptions nrfSystemOptions, NrfSystemOptions oldNrfSystemOptions) {
		Map<String, Object> logMsg = new LinkedHashMap<String, Object>();
		logMsg.clear();
		logMsg.put("logMsg", "validateForwardingConfig()");
		logMsg.put("nrfSystemOptions", nrfSystemOptions);
		logMsg.put("oldNrfSystemOptions", oldNrfSystemOptions);
		logger.info(logMsg.toString());

		if(nrfSystemOptions.getForwardingSystemOptions()!=null) {
			ForwardingSystemOptions forwardingSystemOptions = nrfSystemOptions.getForwardingSystemOptions();
			List<NfConfig> nrfHostConfig = forwardingSystemOptions.getNrfHostConfig();
			ProblemDetails prob = ProblemDetails.forBadRequest();
			prob.setCause("couldnot update forwardingSystemOptions");

			// if any of ForwardingStatus is ENABLED
			if(  ((forwardingSystemOptions.getAccessTokenForwardingStatus() != null) && (forwardingSystemOptions.getAccessTokenForwardingStatus().equals(FeatureStatus.ENABLED))) 
			  || ((forwardingSystemOptions.getDiscoveryForwardingStatus() != null) && (forwardingSystemOptions.getDiscoveryForwardingStatus().equals(FeatureStatus.ENABLED)))
			  || ((forwardingSystemOptions.getProfileRetreivalForwardingStatus() != null) &&  (forwardingSystemOptions.getProfileRetreivalForwardingStatus().equals(FeatureStatus.ENABLED))) 
			  || ((forwardingSystemOptions.getSubscriptionForwardingStatus() != null) && (forwardingSystemOptions.getSubscriptionForwardingStatus().equals(FeatureStatus.ENABLED))) ) {
				// if nrfHostConfig is null
				if(nrfHostConfig==null) {
					// check Db if nrfHostConfig is not present
					if(oldNrfSystemOptions.getForwardingSystemOptions()!=null) { 
						ForwardingSystemOptions oldForwardingSystemOptions = oldNrfSystemOptions.getForwardingSystemOptions();
						if(oldForwardingSystemOptions.getNrfHostConfig()==null || oldForwardingSystemOptions.getNrfHostConfig().isEmpty()) {	
							logMsg.clear();
							logMsg.put("logMsg", "Forwarding is not allowed to be enabled without nrfHostConfig");
							logMsg.put("nrfSystemOptions",nrfSystemOptions);
							logMsg.put("oldNrfSystemOptions",oldNrfSystemOptions);
							logger.error(logMsg.toString());
							prob.setDetail("Forwarding is not allowed to be enabled without nrfHostConfig");
							throw new NrfException(prob);
						}
					}
				}
				// if nrfHostConfig is empty
				else if(nrfHostConfig!=null && nrfHostConfig.isEmpty()) {
					logMsg.clear();
					logMsg.put("logMsg", "nrfHostConfig is not allowed to be empty while enabling forwarding");
					logMsg.put("nrfSystemOptions",nrfSystemOptions);
					logMsg.put("oldNrfSystemOptions",oldNrfSystemOptions);
					logger.error(logMsg.toString());
					prob.setDetail("nrfHostConfig is not allowed to be empty while enabling forwarding");
					throw new NrfException(prob);
				}
			}
			// if nrfHostConfig is empty
			else if(nrfHostConfig!=null && nrfHostConfig.isEmpty()) {
				// check Db if any of ForwardingStatus is ENABLED
				if(oldNrfSystemOptions.getForwardingSystemOptions()!=null) {
					ForwardingSystemOptions olfForwardingSystemOptions = oldNrfSystemOptions.getForwardingSystemOptions();
					if(olfForwardingSystemOptions.getAccessTokenForwardingStatus().equals(FeatureStatus.ENABLED) || olfForwardingSystemOptions.getDiscoveryForwardingStatus().equals(FeatureStatus.ENABLED) ||
							olfForwardingSystemOptions.getProfileRetreivalForwardingStatus().equals(FeatureStatus.ENABLED) || olfForwardingSystemOptions.getSubscriptionForwardingStatus().equals(FeatureStatus.ENABLED)) {
						logMsg.clear();
						logMsg.put("logMsg", "nrfHostConfig is not allowed to be empty when forwarding is already configured as enabled");
						logMsg.put("nrfSystemOptions",nrfSystemOptions);
						logMsg.put("oldNrfSystemOptions",oldNrfSystemOptions);
						logger.error(logMsg.toString());
						prob.setDetail("nrfHostConfig is not allowed to be empty when forwarding is already configured as enabled");
						throw new NrfException(prob);
					}
				}
			}
		}
		
		logMsg.clear();
		logMsg.put("logMsg", "returning from validateForwardingConfig()");
		logger.info(logMsg.toString());
		return;
	}
	
	public void validateSlfSystemOptionsConfig(NrfSystemOptions nrfSystemOptions, NrfSystemOptions oldNrfSystemOptions) {
		Map<String, Object> logMsg = new LinkedHashMap<String, Object>();
		logMsg.clear();
		logMsg.put("logMsg", "validateSlfSystemOptionsConfig()");
		logMsg.put("nrfSystemOptions", nrfSystemOptions);
		logMsg.put("oldNrfSystemOptions", oldNrfSystemOptions);
		logger.info(logMsg.toString());

		if(nrfSystemOptions.getSlfSystemOptions()!=null) {
			SlfSystemOptions slfSystemOptions = nrfSystemOptions.getSlfSystemOptions();
			List<NfConfig> slfHostConfig = slfSystemOptions.getSlfHostConfig();
			List<@NFType String> supportedNfTypeList = slfSystemOptions.getSupportedNfTypeList();
			ProblemDetails prob = ProblemDetails.forBadRequest();
			prob.setCause("couldnot update slfSystemOption");

			// if supportedNfTypeList is present, not empty
			if(supportedNfTypeList!=null && !supportedNfTypeList.isEmpty()) {

				// if slfHostConfig is null
				if(slfHostConfig==null) {
					// check Db if slfHostConfig is not present
					if(oldNrfSystemOptions.getSlfSystemOptions()!=null){
						SlfSystemOptions oldSlfSystemOptions = oldNrfSystemOptions.getSlfSystemOptions();
						if(oldSlfSystemOptions.getSlfHostConfig()==null || oldSlfSystemOptions.getSlfHostConfig().isEmpty()) {
							logMsg.clear();
							logMsg.put("slfHostConfig", "supportedNfTypeList is not allowed to be configured without slfHostConfig");
							logMsg.put("nrfSystemOptions",nrfSystemOptions);
							logMsg.put("oldNrfSystemOptions",oldNrfSystemOptions);
							logger.error(logMsg.toString());
							prob.setDetail("supportedNfTypeList is not allowed to be configured without slfHostConfig");
							throw new NrfException(prob);
						}
					}
				}
				// if slfHostConfig is empty
				else if(slfHostConfig!=null && slfHostConfig.isEmpty()) {
					logMsg.clear();
					logMsg.put("slfHostConfig", "slfHostConfig is not allowed to be empty when supportedNfTypeList is present");
					logMsg.put("nrfSystemOptions",nrfSystemOptions);
					logMsg.put("oldNrfSystemOptions",oldNrfSystemOptions);
					logger.error(logMsg.toString());
					prob.setDetail("slfHostConfig is not allowed to be empty when supportedNfTypeList is present");
					throw new NrfException(prob);
				}
			}
			// supportedNfTypeList is null
			else if(supportedNfTypeList==null) {
				// if slfHostConfig is empty
				if(slfHostConfig!=null && slfHostConfig.isEmpty()) {
					// check Db if supportedNfTypeList is present
					if(oldNrfSystemOptions.getSlfSystemOptions()!=null) {
						SlfSystemOptions oldSlfSystemOptions = oldNrfSystemOptions.getSlfSystemOptions();
						if(oldSlfSystemOptions.getSupportedNfTypeList()!=null 
								&& !oldSlfSystemOptions.getSupportedNfTypeList().isEmpty()) {
							logMsg.clear();
							logMsg.put("logMsg", "slfHostConfig is not allowed to be empty when supportedNfTypeList is already configured");
							logMsg.put("nrfSystemOptions",nrfSystemOptions);
							logMsg.put("oldNrfSystemOptions",oldNrfSystemOptions);
							logger.error(logMsg.toString());
							prob.setDetail("slfHostConfig is not allowed to be empty when supportedNfTypeList is already configured");
							throw new NrfException(prob);
						}
					}
				}
			}
		}
		
		logMsg.clear();
		logMsg.put("logMsg", "return from validateSlfSystemOptionsConfig()");
		logger.info(logMsg.toString());
		return;

	}

	
	public void validateNfAuthenticationErrorResponses(NrfSystemOptions nrfSystemOptions, NrfSystemOptions oldNrfSystemOptions) {
		Map<String, Object> logMsg = new LinkedHashMap<String, Object>();
		logMsg.clear();
		logMsg.put("logMsg", "Entering validateNfAuthenticationErrorResponses() function");
		logMsg.put("nrfSystemOptions", nrfSystemOptions);
		logMsg.put("oldNrfSystemOptions", oldNrfSystemOptions);
		logger.info(logMsg.toString());
		if (nrfSystemOptions.getNfAuthenticationSystemOptions() != null ) {
			if (nrfSystemOptions.getNfAuthenticationSystemOptions().getNfAuthenticationErrorResponses() != null ) {
				List<ErrorInfo> nfAuthenticationErrorResponses = nrfSystemOptions.getNfAuthenticationSystemOptions().getNfAuthenticationErrorResponses();
				for (ErrorInfo nfAuthenticationError : nfAuthenticationErrorResponses) {
					List<ErrorInfo> nfAuthenticationErrorResponsesOld = oldNrfSystemOptions.getNfAuthenticationSystemOptions().getNfAuthenticationErrorResponses();
					for (ErrorInfo nfAuthenticationErrorOld : nfAuthenticationErrorResponsesOld) {
						if(nfAuthenticationError.getErrorCondition().equals(nfAuthenticationErrorOld.getErrorCondition())){
							int errorCode = nfAuthenticationError.getErrorCode();
							String errorCodeGroup = null;
							if(HttpStatus.valueOf(errorCode).is3xxRedirection()) {
								errorCodeGroup = "3xx";
							}
							else if(HttpStatus.valueOf(errorCode).is4xxClientError()) {
								errorCodeGroup = "4xx";
							}
							else if(HttpStatus.valueOf(errorCode).is5xxServerError()) {
								errorCodeGroup = "5xx";
							}
							Object getNrfEngSystemOptions = getNrfEngSystemOptions();
							if(getNrfEngSystemOptions instanceof ProblemDetails) {
								throw new NrfException((ProblemDetails)getNrfEngSystemOptions);
							}
							NrfEngSystemOptions nrfEngSystemOptions = (NrfEngSystemOptions)getNrfEngSystemOptions;
							List<String> redirectURLErrorCodes = nrfEngSystemOptions.getGeneralEngSystemOptions().getRedirectUrlErrorCodes();
							if(redirectURLErrorCodes!=null && 
									(redirectURLErrorCodes.contains(errorCodeGroup) || redirectURLErrorCodes.contains(String.valueOf(errorCode)))) {
								//If error code present in redirectURLErrorCodes, redirectURL must be sent in update request or must already be present in db
								if(nfAuthenticationError.getRedirectUrl()==null && nfAuthenticationErrorOld.getRedirectUrl()==null) {
									logMsg.clear();
									logMsg.put("logMsg", "redirectURL should be configured for redirect error codes");
									logMsg.put("retryAfterErrorCodes",redirectURLErrorCodes);
									logger.error(logMsg.toString());
									ProblemDetails problemDetails = ProblemDetails.forBadRequest();
									problemDetails.setCause("Could not update NrfSystemOptions");
									problemDetails.setDetail("redirectURL should be configured for redirect error codes: "+redirectURLErrorCodes.toString());
									throw new NrfException(problemDetails);
								}
							}
						}
					}
				}
			}			
		}		
		logMsg.clear();
		logMsg.put("logMsg", "Exiting from validateNfAuthenticationErrorResponses() function");
		logger.info(logMsg.toString());
		return;
	}


	
	private void validateAuthFeatureConfig(NrfSystemOptions nrfSystemOptions, NrfSystemOptions oldNrfSystemOptions) {
		Map<String, Object> logMsg = new LinkedHashMap<String, Object>();
		logMsg.clear();
		logMsg.put("logMsg", "validateAuthFeatureConfig()");
		logMsg.put("nrfSystemOptions", nrfSystemOptions);
		logMsg.put("oldNrfSystemOptions", oldNrfSystemOptions);
		logger.info(logMsg.toString());
		ProblemDetails prob = ProblemDetails.forBadRequest();
		if(nrfSystemOptions.getNfAccessTokenSystemOptions() != null) {
			if (nrfSystemOptions.getNfAccessTokenSystemOptions().getAuthFeatureConfig() != null) {
				AuthFeatureConfig authFeatureConfig = nrfSystemOptions.getNfAccessTokenSystemOptions().getAuthFeatureConfig();
				AuthFeatureConfig oldAuthFeatureConfig = oldNrfSystemOptions.getNfAccessTokenSystemOptions().getAuthFeatureConfig();
				if (authFeatureConfig.getAuthFeatureStatus() != null) {
					if (authFeatureConfig.getAuthFeatureStatus().equals(FeatureStatus.ENABLED)) {
                        if ((authFeatureConfig.getAuthConfig() == null && ((oldAuthFeatureConfig.getAuthConfig() == null) || (oldAuthFeatureConfig.getAuthConfig() != null && oldAuthFeatureConfig.getAuthConfig().isEmpty()))) 
                                || (authFeatureConfig.getAuthConfig() != null && authFeatureConfig.getAuthConfig().isEmpty())) {
                            //authFeature is being enabled without authConfig present in the request or in the db.
                            prob.setDetail("authFeature cannot be enabled without the configuring authConfig");
                            prob.setCause("authFeature cannot be enabled without the configuring authConfig");
                            logMsg.clear();
                            logMsg.put("logMsg", "authFeature cannot be enabled without the configuring authConfig");
                            logger.error(logMsg.toString());
                            throw new NrfException(prob);
                        }
					}
				}
			}
		}
		logMsg.clear();
		logMsg.put("logMsg", "return from validateAuthFeatureConfig()");
		logger.info(logMsg.toString());
		return;
	}


}