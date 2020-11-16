// Copyright 2018 (C), Oracle and/or its affiliates. All rights reserved.

package com.oracle.cgbu.cne.nrf.test;

import static org.hamcrest.Matchers.is;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.io.UnsupportedEncodingException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.oracle.cgbu.cne.nrf.PlmnListConverter;
import com.oracle.cgbu.cne.nrf.config.NrfConfigurations;
import com.oracle.cgbu.cne.nrf.config.NrfSystemOptionsManager;
import com.oracle.cgbu.cne.nrf.config.UtilityBeansConfiguration;
import com.oracle.cgbu.cne.nrf.dao.NfInstance;
import com.oracle.cgbu.cne.nrf.dao.NrfSystemOptionsDao;
import com.oracle.cgbu.cne.nrf.domain.FeatureStatus;
import com.oracle.cgbu.cne.nrf.domain.ForwardingData;
import com.oracle.cgbu.cne.nrf.domain.GeneralSystemOptions;
import com.oracle.cgbu.cne.nrf.domain.GenericResponse;
import com.oracle.cgbu.cne.nrf.domain.InvalidParam;
import com.oracle.cgbu.cne.nrf.domain.NfProfile;
import com.oracle.cgbu.cne.nrf.domain.NrfEngSystemOptions;
import com.oracle.cgbu.cne.nrf.domain.NrfSystemOptions;
import com.oracle.cgbu.cne.nrf.domain.Plmn;
import com.oracle.cgbu.cne.nrf.domain.ProblemDetails;
import com.oracle.cgbu.cne.nrf.domain.SearchResult;
import com.oracle.cgbu.cne.nrf.domain.VersionedJsonDoc;
import com.oracle.cgbu.cne.nrf.domain.VersionedJsonDocList;
import com.oracle.cgbu.cne.nrf.metrics.MetricsDimension;
import com.oracle.cgbu.cne.nrf.metrics.NrfMetrics;
import com.oracle.cgbu.cne.nrf.rest.NFDiscoveryController;
import com.oracle.cgbu.cne.nrf.service.NfDiscServiceImpl;
import com.oracle.cgbu.cne.nrf.serviceHelper.ValidationHelper;

import io.micrometer.core.instrument.Counter;
import io.micrometer.core.instrument.Metrics;
import io.micrometer.core.instrument.search.MeterNotFoundException;


@RunWith(SpringRunner.class)
@WebMvcTest(NFDiscoveryController.class)
@ContextConfiguration(classes = {NFDiscoveryController.class, NrfConfigurations.class, NrfMetrics.class, PlmnListConverter.class,MetricsDimension.class, UtilityBeansConfiguration.class })
@TestPropertySource("classpath:application-test.properties")
public class NfDiscoveryControllerTest {

	@Autowired
	private MockMvc mvc;
	
	@MockBean
	private NfDiscServiceImpl service;
	
	@MockBean 
	private ValidationHelper validationHelper;

	
	@MockBean
	NrfSystemOptionsManager nrfSystemOptionsManager;
	
	@Value("${nrf.disc-svc.disc-result-validity-duration}")
	private Duration validityPeriodSecs;
	
	@Autowired
	private ObjectMapper om;
	
	NrfConfigurations nrfConfig = new NrfConfigurations();
	
	private Boolean forwardedRequest = false; 
	
	@Captor
	private ArgumentCaptor<LogEvent> captorLoggingEvent;
	
	@Mock
	private MetricsDimension metricsDimension;

	private Logger logger;
	
	@Mock
	private Appender mockAppender;
	
	@Before
	public void setUp() {
       	nrfConfig.setGlobalConfig(new NrfConfigurations.GlobalConfig());
		nrfConfig.getGlobalConfig().setNrfInstanceId("6faf1bbc-6e4a-4454-a507-a14ef8e1bc5c");
		System.gc();
		MockitoAnnotations.initMocks(this);
		when(mockAppender.getName()).thenReturn("MockAppender");
		when(mockAppender.isStarted()).thenReturn(true);
		when(mockAppender.isStopped()).thenReturn(false);
		logger = (Logger)LogManager.getRootLogger();
		logger.addAppender(mockAppender);
		logger.setLevel(Level.DEBUG);
		NrfSystemOptions nrfSystemOptions = TestDataGenerator.generateNrfSystemOptions();
		NrfEngSystemOptions nrfEngSystemOptions = TestDataGenerator.generateNrfEngSystemOptions();
		when(nrfSystemOptionsManager.getNrfSystemOptions()).thenReturn(nrfSystemOptions);
		when(nrfSystemOptionsManager.getNrfEngSystemOptions()).thenReturn(nrfEngSystemOptions);
	}
	
	@After
	public void teardown() {
		logger.removeAppender(mockAppender);
	}
	
	// given - discovery request 
	// when - target-nf-type key is not given
	// then - return problemDetails
	@Test
	public void givenRequestForDiscovery_whenTargetNfTypeKeyIsInvalid_theReturnProblemDetails() throws Exception{
		Counter s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "AMF").tag("TargetNfType","PCF").counter();
		double prev_requests = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
	               .tag("RequesterNfType", "AMF").tag("TargetNfType","PCF").tag("HttpStatusCode","400").counter();
		double prev_response = (s != null) ? s.count() : 0;
		
		s= Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "AMF").tag("TargetNfType","UNKNOWN").counter();
		double prev_requests_1 =  (s != null) ? s.count() : 0;
		
		s= Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
	               .tag("RequesterNfType", "AMF").tag("TargetNfType","UNKNOWN").tag("HttpStatusCode","400").counter();
		double prev_response_1 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
                .tag("RequesterNfType", "AMF").counter();
		double prev_perService = (s != null) ? s.count() : 0;
		
		long count = 0;
		try {
			count = Metrics.globalRegistry.get("ocnrf.message.processing.time")
					.tag("RequesterNfType", "AMF").tag("ServiceOperation", "NfDiscover").timer().count();
		} catch(MeterNotFoundException e) {
			count = 0;
		}
		
		ProblemDetails prob = ProblemDetails.forBadRequest();
		prob.setDetail("Invalid input data");
		prob.addInvalidParam(new InvalidParam("targetNfType","must not be null"));
		
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("Target-nf-type=PCF&requester-nf-type=AMF");
                return request;
            }
        }))
        		.andExpect(status().isBadRequest())
        		.andReturn();
		
		MockHttpServletResponse respObj = res.getResponse();
		
		String jsonStr = respObj.getContentAsString();

		ProblemDetails retObj = om.readValue(jsonStr, ProblemDetails.class);
		Assert.assertEquals(prob, retObj);
		
		// No Change in these metrics
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "AMF").tag("TargetNfType","PCF").counter();
		double current = (s != null) ? s.count() : 0;
		Assert.assertEquals(prev_requests, current,0);
		s= Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
	               .tag("RequesterNfType", "AMF").tag("TargetNfType","PCF").counter();
		current = (s != null) ? s.count() : 0;
		Assert.assertEquals(prev_response, current,0);
		s= Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
                .tag("RequesterNfType", "UNKNOWN").counter();
		current = (s != null) ? s.count() : 0;
		Assert.assertEquals(prev_perService, current,0);
		
	    // Updated metrics
	    Assert.assertEquals(prev_requests_1+1,Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "AMF").tag("TargetNfType","UNKNOWN").counter().count(),0);
	    Assert.assertEquals(prev_response_1+1, Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
				               .tag("RequesterNfType", "AMF").tag("TargetNfType","UNKNOWN").tag("HttpStatusCode","400").counter().count(),0);
	    Assert.assertEquals(count+1, Metrics.globalRegistry.get("ocnrf.message.processing.time")
				.tag("RequesterNfType", "AMF").tag("ServiceOperation", "NfDiscover").timer().count());
	}
	
	// given - discovery request 
	// when - request-nf-type key is not given
	// then - return problemDetails
	/*
	@Test
	public void givenRequestForDiscovery_whenRequesterNfTypeKeyIsInvalid_theReturnProblemDetails() throws Exception{

		Counter s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "AMF").tag("TargetNfType","PCF").counter();
		double prev_requests = (s != null) ? s.count() : 0;

		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
				.tag("RequesterNfType", "AMF").tag("TargetNfType","PCF").tag("HttpStatusCode","400").counter();
		double prev_response = (s != null) ? s.count() : 0;

		s= Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "UNKNOWN").tag("TargetNfType","AMF").counter();
		double prev_requests_1 =  (s != null) ? s.count() : 0;

		s= Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
				.tag("RequesterNfType", "UNKNOWN").tag("TargetNfType","AMF").tag("HttpStatusCode","400").counter();
		double prev_response_1 = (s != null) ? s.count() : 0;

		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
				.tag("RequesterNfType", "AMF").counter();
		double prev_perService = (s != null) ? s.count() : 0;

		long count = 0;
		try {
			count = Metrics.globalRegistry.get("ocnrf.message.processing.time")
					.tag("RequesterNfType", "UNKNOWN").tag("ServiceOperation", "NfDiscover").timer().count();
		} catch(MeterNotFoundException e) {
			count = 0;
		}

		ProblemDetails prob = ProblemDetails.forBadRequest();
		prob.setDetail("Invalid input data");
		prob.addInvalidParam(new InvalidParam("requesterNfType","must not be null"));

		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=PCF&Requester-nf-type=AMF");
                return request;
            }
        })).andExpect(status().isBadRequest())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();

		ProblemDetails retObj = om.readValue(jsonStr, ProblemDetails.class);
		Assert.assertEquals(prob, retObj);

		// No Change in these metrics
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "AMF").tag("TargetNfType","PCF").counter();
		double current = (s != null) ? s.count() : 0;
		Assert.assertEquals(prev_requests, current,0);
		s= Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
				.tag("RequesterNfType", "AMF").tag("TargetNfType","PCF").counter();
		current = (s != null) ? s.count() : 0;
		Assert.assertEquals(prev_response, current,0);
		s= Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
				.tag("RequesterNfType", "UNKNOWN").counter();
		current = (s != null) ? s.count() : 0;
		Assert.assertEquals(prev_perService, current,0);

		// Updated metrics
		Assert.assertEquals(prev_requests_1+1,Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "UNKNOWN").tag("TargetNfType","PCF").counter().count(),0);
		Assert.assertEquals(prev_response_1+1, Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
				.tag("RequesterNfType", "UNKNOWN").tag("TargetNfType","PCF").tag("HttpStatusCode","400").counter().count(),0);
		Assert.assertEquals(count+1, Metrics.globalRegistry.get("ocnrf.message.processing.time")
					.tag("RequesterNfType", "UNKNOWN").tag("ServiceOperation", "NfDiscover").timer().count());
	}*/
	
	// given - discovery request 
	// when - target-nf-type is invalid
	// then - return problemDetails
	@Test
	public void givenRequestForDiscovery_whenTargetNfTypeIsInvalid_theReturnProblemDetails() throws Exception{
		Counter s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "AMF").tag("TargetNfType","PCF").counter();
		double prev_requests = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
	               .tag("RequesterNfType", "AMF").tag("TargetNfType","PCF").tag("HttpStatusCode","400").counter();
		double prev_response = (s != null) ? s.count() : 0;
		
		s= Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "AMF").tag("TargetNfType","UNKNOWN").counter();
		double prev_requests_1 =  (s != null) ? s.count() : 0;
		
		s= Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
	               .tag("RequesterNfType", "AMF").tag("TargetNfType","UNKNOWN").tag("HttpStatusCode","400").counter();
		double prev_response_1 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
                .tag("RequesterNfType", "AMF").counter();
		double prev_perService = (s != null) ? s.count() : 0;
		
		ProblemDetails prob = ProblemDetails.forBadRequest();
		prob.setDetail("Invalid input data");
		prob.addInvalidParam(new InvalidParam("targetNfType","invalid NFType"));

		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type={[\"PCF\"]}&requester-nf-type=AMF");
                return request;
            }
        })).andExpect(status().isBadRequest())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();

		ProblemDetails retObj = om.readValue(jsonStr, ProblemDetails.class);
		Assert.assertEquals(prob, retObj);
		
		// No Change in these metrics
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "AMF").tag("TargetNfType","PCF").counter();
		
		double current = (s != null) ? s.count() : 0;
		Assert.assertEquals(prev_requests, current,0);
		s= Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
	               .tag("RequesterNfType", "AMF").tag("TargetNfType","PCF").tag("HttpStatusCode","400").counter();
		current = (s != null) ? s.count() : 0;
		Assert.assertEquals(prev_response, current,0);
		s= Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
                .tag("RequesterNfType", "AMF").counter();
		current = (s != null) ? s.count() : 0;
		Assert.assertEquals(prev_perService, current,0);
		
	    // Updated metrics
	    Assert.assertEquals(prev_requests_1+1,Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "AMF").tag("TargetNfType","UNKNOWN").counter().count(),0);
	    Assert.assertEquals(prev_response_1+1, Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
				               .tag("RequesterNfType", "AMF").tag("TargetNfType","UNKNOWN").tag("HttpStatusCode","400").counter().count(),0);
	}
	
	// given - discovery request
	// when - target-nf-type is 'AMF'
	// then - nfProfiles matching the target-nf-type are returned
	@Test
	public void givenRequestForDiscovery_whenTargetNfTypeValid_theReturnJsonStructure() throws Exception{
		Counter s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "PCF").tag("TargetNfType","AMF").counter();
		double prev_requests = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
	               .tag("RequesterNfType", "PCF").tag("TargetNfType","AMF").tag("HttpStatusCode","200").counter();
		double prev_response = (s != null) ? s.count() : 0;
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
                .tag("RequesterNfType", "PCF").counter();
		double prev_perService = (s != null) ? s.count() : 0;
		long count = 0;
		try {
			count = Metrics.globalRegistry.get("ocnrf.message.processing.time")
					.tag("RequesterNfType", "PCF").tag("ServiceOperation", "NfDiscover").timer().count();
		} catch(MeterNotFoundException e) {
			count = 0;
		}
		
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));

		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfProfiles);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();
		SearchResult retObj = om.readValue(jsonStr, SearchResult.class);
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
		Assert.assertEquals("2", retObj.getNrfSupportedFeatures());
		//Assert additionalAttributes is null
		Iterator<NfProfile> iter = retObj.getNfInstances().iterator();
		while(iter.hasNext()) {
			NfProfile profile = iter.next();
			Assert.assertEquals(null, profile.getAdditionalAttributes());
		}
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "PCF").tag("TargetNfType","AMF").counter();
		double after_requests = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
	               .tag("RequesterNfType", "PCF").tag("TargetNfType","AMF").tag("HttpStatusCode","200").counter();
		double after_response = (s != null) ? s.count() : 0;
		
	    // Updated metrics
	    Assert.assertEquals(prev_requests+1,after_requests,0);
	    Assert.assertEquals(prev_response+1, after_response,0);
	    
	    s= Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
                .tag("RequesterNfType", "PCF").counter();
		double current = (s != null) ? s.count() : 0;
		Assert.assertEquals(prev_perService, current,0);
		Assert.assertEquals(count+1, Metrics.globalRegistry.get("ocnrf.message.processing.time")
				.tag("RequesterNfType", "PCF").tag("ServiceOperation", "NfDiscover").timer().count());
	}
	
	// given - discovery request
	// when - target-nf-type is 'AMF' but no nfProfile exits in database
	// then - return problemDetails
	@Test
	public void givenRequestForDiscovery_whenTargetNfTypeValid_theReturnProblemDetails() throws Exception{
        HashMap<String,Object> reHashMap = new HashMap<String, Object>();
		ProblemDetails problemDetails = ProblemDetails.forNotFound();
		reHashMap.put("response", problemDetails);
		reHashMap.put("profileSearched", false);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(problemDetails);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();
		SearchResult retObj = om.readValue(jsonStr, SearchResult.class);
		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
		Assert.assertEquals(0, nfProfiles.size());
		Iterator<NfProfile> iter = nfProfiles.iterator();
		while(iter.hasNext()) {
			NfProfile profile = iter.next();
			Assert.assertEquals(null, profile.getAdditionalAttributes());
		}
	}
	
	@Test
	public void givenRequestForDiscovery_wehnSupportedFeaturesIsInvalid_theReturnProblemDetails() throws Exception{
		Counter s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "PCF").tag("TargetNfType","AMF").counter();
		double prev_requests = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
	               .tag("RequesterNfType", "PCF").tag("TargetNfType","AMF").tag("HttpStatusCode","400").counter();
		double prev_response = (s != null) ? s.count() : 0;
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
                .tag("RequesterNfType", "PCF").counter();
		double prev_perService = (s != null) ? s.count() : 0;
		
		ProblemDetails prob = ProblemDetails.forBadRequest();
		prob.setDetail("Invalid input data");
	    prob.addInvalidParam(new InvalidParam("supported-features","'supported-features' is invalid"));

		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&supported-features=x");
                return request;
            }
        })).andExpect(status().isBadRequest())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();

		ProblemDetails retObj = om.readValue(jsonStr, ProblemDetails.class);
		Assert.assertEquals(prob, retObj);
		
	    // Updated metrics
	    Assert.assertEquals(prev_requests+1,Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "PCF").tag("TargetNfType","AMF").counter().count(),0);
	    Assert.assertEquals(prev_response+1, Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
				               .tag("RequesterNfType", "PCF").tag("TargetNfType","AMF").tag("HttpStatusCode","400").counter().count(),0);
	    
	    s= Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
                .tag("RequesterNfType", "PCF").counter();
		double current = (s != null) ? s.count() : 0;
		Assert.assertEquals(prev_perService, current,0);
	}
	
	// given - discovery request
	// when - target-nf-type is 'AMF' but discoverNfProfiles in service method returns ProblemDetails object
	// then - return problemDetails
	@Test
	public void givenRequestForDiscovery_whenTargetNfType_theReturnProblemDetails() throws Exception{

		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);

		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);

		ProblemDetails problemDetails = ProblemDetails.forBadRequest();
		reHashMap.put("response", problemDetails);
		reHashMap.put("profileSearched",false);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfProfiles);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);

		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF");
                return request;
            }
        })).andExpect(status().isBadRequest())
		   .andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();

		ProblemDetails retObj = om.readValue(jsonStr, ProblemDetails.class);
		Assert.assertEquals(problemDetails, retObj);
	}
	
	@Test
	public void givenRequestForDiscovery_withInvalidAmfSetId_thenReturnProblemDetails() throws Exception{
		
		ProblemDetails problemDetails = ProblemDetails.forBadRequest();
		problemDetails.setDetail("Invalid input data");
		problemDetails.addInvalidParam(new InvalidParam("amfInfo","format not valid"));

		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&amf-set-id=!");
                return request;
            }
        })).andExpect(status().isBadRequest())
		   .andReturn();

		MockHttpServletResponse respObj = res.getResponse();
		String jsonStr = respObj.getContentAsString();
		ProblemDetails retObj = om.readValue(jsonStr, ProblemDetails.class);
		Assert.assertEquals(problemDetails, retObj);
		
		NrfSystemOptionsDao nrfSystemOptionsDao = TestDataGenerator.generateNrfSystemOptionsDao();
		NrfSystemOptions nrfSystemOptions = (NrfSystemOptions) nrfSystemOptionsDao.toDomain("v1");
		List<Plmn> nrfPlmnList = new ArrayList<>();
		Plmn add = new Plmn("310","14");
		nrfPlmnList.add(add);
		GeneralSystemOptions general = new GeneralSystemOptions();
		general.setNrfPlmnList(nrfPlmnList);
		general.setEnableF3(false);
		general.setEnableF5(true);
		general.setMaximumHopCount(2);
		general.setDefaultLoad(5);
		general.setDefaultPriority(100);
		general.setAddLoadInNFProfile(false);
		general.setAddPriorityInNFProfile(false);
		nrfSystemOptions.setGeneralSystemOptions(general);
		when(nrfSystemOptionsManager.getNrfSystemOptions()).thenReturn(nrfSystemOptions);
		res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&amf-set-id=!");
                return request;
            }
        })).andExpect(status().isBadRequest())
		   .andReturn();

		respObj = res.getResponse();
		jsonStr = respObj.getContentAsString();
		retObj = om.readValue(jsonStr, ProblemDetails.class);
		Assert.assertEquals(problemDetails, retObj);
		
		nrfSystemOptions = TestDataGenerator.generateNrfSystemOptions();
		general = new GeneralSystemOptions();
		general.setNrfPlmnList(nrfPlmnList);
		general.setEnableF3(true);
		general.setEnableF5(false);
		general.setMaximumHopCount(2);
		general.setDefaultLoad(5);
		general.setDefaultPriority(100);
		general.setAddLoadInNFProfile(false);
		general.setAddPriorityInNFProfile(false);
		nrfSystemOptions.setGeneralSystemOptions(general);
		when(nrfSystemOptionsManager.getNrfSystemOptions()).thenReturn(nrfSystemOptions);
		
		res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&amf-set-id=!");
                return request;
            }
        })).andExpect(status().isBadRequest())
		   .andReturn();

		respObj = res.getResponse();
		jsonStr = respObj.getContentAsString();
		retObj = om.readValue(jsonStr, ProblemDetails.class);
		Assert.assertEquals(problemDetails, retObj);
		
	}
	
	@Test
	public void givenRequestForDiscovery_withInvalidAmfSetId_thenReturnNfProfile() throws Exception{
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
        nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		NrfSystemOptionsDao nrfSystemOptionsDao = TestDataGenerator.generateNrfSystemOptionsDao();
		NrfSystemOptions nrfSystemOptions = (NrfSystemOptions) nrfSystemOptionsDao.toDomain("v1");
		List<Plmn> nrfPlmnList = new ArrayList<>();
		Plmn add = new Plmn("310","14");
		nrfPlmnList.add(add);
		GeneralSystemOptions general = new GeneralSystemOptions();
		general.setNrfPlmnList(nrfPlmnList);
		general.setEnableF3(false);
		general.setEnableF5(false);
		general.setMaximumHopCount(2);
		general.setDefaultLoad(5);
		general.setDefaultPriority(100);
		general.setAddLoadInNFProfile(false);
		general.setAddPriorityInNFProfile(false);
		nrfSystemOptions.setGeneralSystemOptions(general);
		List<VersionedJsonDoc> list = new ArrayList<>();
		VersionedJsonDoc versionJsonDoc = new VersionedJsonDoc();
		versionJsonDoc.setVersion("v1");
		versionJsonDoc.setDoc(nrfSystemOptions.toString());
		list.add(versionJsonDoc);
		VersionedJsonDocList versionJsonDocList = new VersionedJsonDocList();
		versionJsonDocList.setVersionedJsonDocList(list);
		nrfSystemOptionsDao.setConfigurationJsonDocList(versionJsonDocList.toString());
		when(nrfSystemOptionsManager.getNrfSystemOptions()).thenReturn(nrfSystemOptions);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfProfiles);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res1 = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&amf-set-id=!");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj1 = res1.getResponse();
		String jsonStr1 = respObj1.getContentAsString();
		Assert.assertFalse(jsonStr1.contains("nrfSupportedFeatures"));
		SearchResult retObject = om.readValue(jsonStr1, SearchResult.class);
		Assert.assertEquals(nfProfiles, retObject.getNfInstances());
		//Asset additionalAttributes are set to null
		Iterator<NfProfile> iter = retObject.getNfInstances().iterator();
		while(iter.hasNext()) {
			NfProfile profile = iter.next();
			Assert.assertEquals(null, profile.getAdditionalAttributes());
		}
	}
	
	@Test
	public void givenRequestForDiscovery_withInvalidAmfRegionId_thenReturnProblemDetails() throws Exception{
		ProblemDetails problemDetails = ProblemDetails.forBadRequest();
		problemDetails.setDetail("Invalid input data");
		problemDetails.addInvalidParam(new InvalidParam("amfInfo","format not valid"));

		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&amf-region-id=!");
                return request;
            }
        })).andExpect(status().isBadRequest())
		   .andReturn();

		MockHttpServletResponse respObj = res.getResponse();
		String jsonStr = respObj.getContentAsString();
		ProblemDetails retObj = om.readValue(jsonStr, ProblemDetails.class);
		Assert.assertEquals(problemDetails, retObj);
		
		NrfSystemOptionsDao nrfSystemOptionsDao = TestDataGenerator.generateNrfSystemOptionsDao();
		NrfSystemOptions nrfSystemOptions = (NrfSystemOptions) nrfSystemOptionsDao.toDomain("v1");
		List<Plmn> nrfPlmnList = new ArrayList<>();
		Plmn add = new Plmn("310","14");
		nrfPlmnList.add(add);
		GeneralSystemOptions general = new GeneralSystemOptions();
		general.setNrfPlmnList(nrfPlmnList);
		general.setEnableF3(false);
		general.setEnableF5(true);
		general.setMaximumHopCount(2);
		general.setDefaultLoad(5);
		general.setDefaultPriority(100);
		general.setAddLoadInNFProfile(false);
		general.setAddPriorityInNFProfile(false);
		nrfSystemOptions.setGeneralSystemOptions(general);
		when(nrfSystemOptionsManager.getNrfSystemOptions()).thenReturn(nrfSystemOptions);
		res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&amf-region-id=!");
                return request;
            }
        })).andExpect(status().isBadRequest())
		   .andReturn();

		respObj = res.getResponse();
		jsonStr = respObj.getContentAsString();
		retObj = om.readValue(jsonStr, ProblemDetails.class);
		Assert.assertEquals(problemDetails, retObj);
		
		nrfSystemOptions = TestDataGenerator.generateNrfSystemOptions();
		general = new GeneralSystemOptions();
		general.setNrfPlmnList(nrfPlmnList);
		general.setEnableF3(true);
		general.setEnableF5(false);
		general.setMaximumHopCount(2);
		general.setDefaultLoad(5);
		general.setDefaultPriority(100);
		general.setAddLoadInNFProfile(false);
		general.setAddPriorityInNFProfile(false);
		nrfSystemOptions.setGeneralSystemOptions(general);
		when(nrfSystemOptionsManager.getNrfSystemOptions()).thenReturn(nrfSystemOptions);
		res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&amf-region-id=!");
                return request;
            }
        })).andExpect(status().isBadRequest())
		   .andReturn();

		respObj = res.getResponse();
		jsonStr = respObj.getContentAsString();
		retObj = om.readValue(jsonStr, ProblemDetails.class);
		Assert.assertEquals(problemDetails, retObj);		               
    }
    
	@Test
	public void givenRequestForDiscovery_withInvalidAmfRegionId_thenReturnNfProfile() throws Exception{
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
        nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		NrfSystemOptionsDao nrfSystemOptionsDao = TestDataGenerator.generateNrfSystemOptionsDao();
		NrfSystemOptions nrfSystemOptions = (NrfSystemOptions) nrfSystemOptionsDao.toDomain("v1");
		List<Plmn> nrfPlmnList = new ArrayList<>();
		Plmn add = new Plmn("310","14");
		nrfPlmnList.add(add);
		GeneralSystemOptions general = new GeneralSystemOptions();
		general.setNrfPlmnList(nrfPlmnList);
		general.setEnableF3(false);
		general.setEnableF5(false);
		general.setMaximumHopCount(2);
		general.setDefaultLoad(5);
		general.setDefaultPriority(100);
		general.setAddLoadInNFProfile(false);
		general.setAddPriorityInNFProfile(false);
		nrfSystemOptions.setGeneralSystemOptions(general);
		when(nrfSystemOptionsManager.getNrfSystemOptions()).thenReturn(nrfSystemOptions);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfProfiles);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res1 = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&amf-region-id=!");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj1 = res1.getResponse();
		String jsonStr1 = respObj1.getContentAsString();
		Assert.assertFalse(jsonStr1.contains("nrfSupportedFeatures"));
		SearchResult retObject = om.readValue(jsonStr1, SearchResult.class);
		Assert.assertEquals(nfProfiles, retObject.getNfInstances());
	}
	
	@Test
	public void testDiscoverWithInvalidNfType() throws UnsupportedEncodingException, Exception {
		mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=CUSTOM&requester-nf-type=abc");
                return request;
            }
        })).andExpect(status().isBadRequest())
		        .andExpect(jsonPath("$.title", is("Bad Request")))
				.andExpect(jsonPath("$.cause", is("Bad Request")));
	}
	
	@Test
	public void testDiscover() throws UnsupportedEncodingException, Exception {
		ProblemDetails problemDetails = ProblemDetails.forNotFound();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		reHashMap.put("response",problemDetails);
		reHashMap.put("profileSearched", false);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(reHashMap);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("service-names=service-1,service-2&target-nf-type=PCF&requester-nf-type=AMF&requester-nf-instance-fqdn=requester-nf.oracle.com&target-plmn-list={\"mcc\":\"001\",\"mnc\":\"04\"}&requester-plmn-list={\"mcc\":\"001\",\"mnc\":\"04\"}&snssais={\"sd\":\"432023\",\"sst\":2}&snssais={\"sd\":\"432030\",\"sst\":3}");
                return request;
            }
        }));
	}	

	@Test
	public void testDiscoverWithCustomNfType() throws UnsupportedEncodingException, Exception {
		Counter s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "CUSTOM_NF1").tag("TargetNfType","CUSTOM_PCF").counter();
		double prev_requests = (s != null) ? s.count() : 0;
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
	               .tag("RequesterNfType", "CUSTOM_NF1").tag("TargetNfType","CUSTOM_PCF").tag("HttpStatusCode","400").counter();
		double prev_response = (s != null) ? s.count() : 0;
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
                .tag("RequesterNfType", "CUSTOM_NF1").counter();
		double prev_perService = (s != null) ? s.count() : 0;
		ProblemDetails problemDetails = ProblemDetails.forNotFound();
		reHashMap.put("response", problemDetails);
		reHashMap.put("profileSearched", false);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(problemDetails);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("service-names=service-1,service-2&target-nf-type=CUSTOM_PCF&requester-nf-type=CUSTOM_NF1&requester-nf-instance-fqdn=requester-nf.oracle.com&target-plmn-list={\"mcc\":\"001\",\"mnc\":\"04\"}&requester-plmn-list={\"mcc\":\"001\",\"mnc\":\"04\"}&snssais={\"sd\":\"432023\",\"sst\":2}");
                return request;
            }
        }));
	    // Updated metrics - checks 404 
	    Assert.assertEquals(prev_requests+1,Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "CUSTOM_NF1").tag("TargetNfType","CUSTOM_PCF").counter().count(),0);
	    Assert.assertEquals(prev_response+1, Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
				               .tag("RequesterNfType", "CUSTOM_NF1").tag("TargetNfType","CUSTOM_PCF").tag("HttpStatusCode","200").counter().count(),0);
	    
	    //2 services present
	    int size = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
                .tag("RequesterNfType", "CUSTOM_NF1").counters().size();
		Assert.assertEquals(2, size,0);
		Assert.assertEquals(prev_perService+1, Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
        .tag("RequesterNfType", "CUSTOM_NF1").tag("ServiceName", "service-1").counter().count(),0);
		Assert.assertEquals(prev_perService+1, Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
		        .tag("RequesterNfType", "CUSTOM_NF1").tag("ServiceName", "service-2").counter().count(),0);
		
	}
	
	// given - discovery request 
	// when - service-names has invalid values
	// then - return problemDetails
	@Test
	public void givenRequestForDiscovery_whenServiceNamesIsInvalid_theReturnProblemDetails() throws Exception{
		Counter s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "AMF").tag("TargetNfType","PCF").counter();
		double prev_requests = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
	               .tag("RequesterNfType", "AMF").tag("TargetNfType","PCF").tag("HttpStatusCode","400").counter();
		double prev_response = (s != null) ? s.count() : 0;
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
                .tag("RequesterNfType", "AMF").counter();
		double prev_perService = (s != null) ? s.count() : 0;
		
		
		ProblemDetails prob = ProblemDetails.forBadRequest();
		prob.setDetail("Invalid input data");
		prob.addInvalidParam(new InvalidParam("service-names","'serviceName' should be a valid value"));
		
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=PCF&requester-nf-type=AMF&service-names=[\"namf!*mt\",\"namf-$evts\"]");
                return request;
            }
        })).andExpect(status().isBadRequest())
        		.andReturn();
		
		MockHttpServletResponse respObj = res.getResponse();
		
		String jsonStr = respObj.getContentAsString();

		ProblemDetails retObj = om.readValue(jsonStr, ProblemDetails.class);
		Assert.assertEquals(prob, retObj);
		
		
		res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=PCF&requester-nf-type=AMF&service-names=[namf-mt,namf-evts]");
                return request;
            }
        })).andExpect(status().isBadRequest())
        		.andReturn();
		ProblemDetails prob1 = ProblemDetails.forBadRequest();
		prob1.setDetail("Invalid input data");
		prob1.addInvalidParam(new InvalidParam("service-names","'serviceName' is of invalid type"));
		
        respObj = res.getResponse();
		jsonStr = respObj.getContentAsString();
		retObj = om.readValue(jsonStr, ProblemDetails.class);
		Assert.assertEquals(prob1, retObj);
		
	    // Updated metrics
	    Assert.assertEquals(prev_requests+2,Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "AMF").tag("TargetNfType","PCF").counter().count(),0);
	    Assert.assertEquals(prev_response+2, Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
				               .tag("RequesterNfType", "AMF").tag("TargetNfType","PCF").tag("HttpStatusCode","400").counter().count(),0);
	    
	    s= Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
                .tag("RequesterNfType", "AMF").counter();
		double current = (s != null) ? s.count() : 0;
		Assert.assertEquals(prev_perService, current,0);
		
	}
	
	// given - discovery request
	// when - service-names defined by 5GC
	// then - nfProfiles matching those service-names
	@Test
	public void givenRequestForDiscovery_whenServiceNamesAre5GCDefined_theReturnJsonStructure() throws Exception{

		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.getNfServices().get(0).setServiceName("namf-mt");
		
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.getNfServices().get(1).setServiceName("namf-evts");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&service-names=namf-mt,namf-evts");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();

		SearchResult retObj = om.readValue(jsonStr, new TypeReference<SearchResult>() {});
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());

		//forbidden status is returned 
		ProblemDetails prob = ProblemDetails.forForbidden();
		prob.setCause("requester-nf-type not allowed to discover"
				+ " the instances of this target-nf-type");
		prob.setDetail("requester-nf-type not allowed to discover"
				+ " the instances of this target-nf-type");
		reHashMap.put("response", prob);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=NSSF&service-names=namf-mt,namf-evts");
                return request;
            }
        })).andExpect(status().isForbidden())
				.andReturn();
		respObj = res.getResponse();
		jsonStr = respObj.getContentAsString();
		ProblemDetails problemDetail = om.readValue(jsonStr, new TypeReference<ProblemDetails>() {});
		Assert.assertEquals(prob,problemDetail);
		//forbidden status is returned 
		res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&requester-nf-instance-fqdn=abc.com");
                return request;
            }
        })).andExpect(status().isForbidden())
				.andReturn();
		respObj = res.getResponse();
		jsonStr = respObj.getContentAsString();
		problemDetail = om.readValue(jsonStr, new TypeReference<ProblemDetails>() {});
		Assert.assertEquals(prob,problemDetail);
		//not found status is returned 
		prob = ProblemDetails.forNotFound();
		prob.setCause("No NF Instance Found");
		prob.setDetail("No NF Instance Found");
		reHashMap.put("response", prob);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		
		res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&service-names=[\"abc\",\"abcd\"]");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();
		respObj = res.getResponse();
		jsonStr = respObj.getContentAsString();
		retObj = om.readValue(jsonStr, new TypeReference<SearchResult>() {});
		Assert.assertEquals(0, retObj.getNfInstances().size());
	}
	
	// given - discovery request
	// when - service-names are valid
	// then - nfProfiles matching those service-names
	@Test
	public void givenRequestForDiscovery_whenServiceNamesValid_theReturnJsonStructure() throws Exception{

		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.getNfServices().get(0).setServiceName("amf-5g-policy-1");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.getNfServices().get(1).setServiceName("amf-5g-control-1");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&service-names=\"amf-5g-policy-1\",\"amf-5g-control-1\"");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();

		SearchResult retObj = om.readValue(jsonStr, new TypeReference<SearchResult>() {});
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
	}
	
	// given - discovery request
	// when -  pdu-session-types is valid
	// then - nfProfiles matching those pdu-session-types
	// with - pdu-session-types=IPV4,IPV6,ETHERNET
	@Test
	public void givenRequestForDiscovery_whenPduSessionTypesValid_theReturnJsonStructure() throws Exception{

		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("UPF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("UPF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=UPF&requester-nf-type=PCF&pdu-session-types=IPV4,IPV6,ETHERNET");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();

		SearchResult retObj = om.readValue(jsonStr, new TypeReference<SearchResult>() {});
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
	}
	
	// given - discovery request
	// when -  pdu-session-types is valid
	// then - nfProfiles matching those pdu-session-types
	// with - pdu-session-types=[\"IPV4\",\"IPV6\",\"ETHERNET\"]
	@Test
	public void givenRequestForDiscovery_whenPduSessionTypesIsValid_theReturnJsonStructure() throws Exception{

		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		HashMap<String, Object> resHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("UPF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("UPF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		resHashMap.put("response", nfProfiles);
		resHashMap.put("profileSearched", false);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(resHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=UPF&requester-nf-type=PCF&pdu-session-types=[\"IPV4\",\"IPV6\",\"ETHERNET\"]");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();

		SearchResult retObj = om.readValue(jsonStr, new TypeReference<SearchResult>() {});
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
	}
	
	// given - discovery request
	// when -  pdu-session-types is valid
	// then - nfProfiles matching those pdu-session-types
	// with - pdu-session-types=\"IPV4\",\"IPV6\",\"ETHERNET\"
	@Test
	public void givenRequestForDiscovery_whenPduSessionTypesIsCorrect_theReturnJsonStructure() throws Exception{

		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("UPF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("UPF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=UPF&requester-nf-type=PCF&pdu-session-types=\"IPV4\",\"IPV6\",\"ETHERNET\"");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();

		SearchResult retObj = om.readValue(jsonStr, new TypeReference<SearchResult>() {});
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
	}
	
	// given - discovery request
	// when -  pdu-session-types is valid
	// then - nfProfiles matching those pdu-session-types
	// with - pdu-session-types=%22IPV4%22%2C%22IPV6%22%2C%22ETHERNET%22
	@Test
	public void givenRequestForDiscovery_whenPduSessionTypeCorrect_theReturnJsonStructure() throws Exception{

		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("UPF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("UPF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=UPF&requester-nf-type=PCF&pdu-session-types=%22IPV4%22%2C%22IPV6%22%2C%22ETHERNET%22");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();

		SearchResult retObj = om.readValue(jsonStr, new TypeReference<SearchResult>() {});
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
	}
	
	// given - discovery request
	// when -  pdu-session-types is valid
	// then - nfProfiles matching those pdu-session-types
	// with - pdu-session-types=%5B%22IPV4%22%2C%22IPV6%22%2C%22ETHERNET%22%5D
	@Test
	public void givenRequestForDiscovery_whenPduSessionTypesCorrect_theReturnJsonStructure() throws Exception{

		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("UPF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("UPF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=UPF&requester-nf-type=PCF&pdu-session-types=%5B%22IPV4%22%2C%22IPV6%22%2C%22ETHERNET%22%5D");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();

		SearchResult retObj = om.readValue(jsonStr, new TypeReference<SearchResult>() {});
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
	}
	
	// given - discovery request
	// when -  target-plmn-list is valid, and plmnList of Nf are absent hence nrf plmnList is used 
	// then - nfProfiles matching those target-plmn-list
	// with - target-plmn-list={\"mcc\":\"310\",\"mnc\":\"14\"},{\"mcc\":\"301\",\"mnc\":\"100\"}
	@Test
	public void givenRequestForDiscovery_whenTargetPlmnListValid_theReturnJsonStructure() throws Exception{

		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.setPlmnList(null);
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.setPlmnList(Arrays.asList(new Plmn("310","14"),new Plmn("450","05") ));
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&target-plmn-list={\"mcc\":\"310\",\"mnc\":\"14\"},{\"mcc\":\"301\",\"mnc\":\"100\"}");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();

		SearchResult retObj = om.readValue(jsonStr, new TypeReference<SearchResult>() {});
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
	}
	
	// given - discovery request
	// when -  target-plmn-list is valid, and plmnList of Nf are absent hence nrf plmnList is used 
	// then - nfProfiles matching those target-plmn-list
	// with - target-plmn-list=[{\"mcc\":\"310\",\"mnc\":\"14\"},{\"mcc\":\"301\",\"mnc\":\"100\"}]
	@Test
	public void givenRequestForDiscovery_whenSearchTargetPlmnListValid_theReturnJsonStructure() throws Exception{

		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.setPlmnList(null);
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.setPlmnList(Arrays.asList(new Plmn("310","14"),new Plmn("450","05") ));
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&target-plmn-list=[{\"mcc\":\"310\",\"mnc\":\"14\"},{\"mcc\":\"301\",\"mnc\":\"100\"}]");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();

		SearchResult retObj = om.readValue(jsonStr, new TypeReference<SearchResult>() {});
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
	}
	
	// given - discovery request
	// when -  target-plmn-list is valid, and plmnList of Nf are absent hence nrf plmnList is used 
	// then - nfProfiles matching those target-plmn-list
	// with - target-plmn-list=%7B%22mcc%22%3A%22310%22%2C%22mnc%22%3A%2214%22%7D%2C%7B%22mcc%22%3A%22301%22%2C%22mnc%22%3A%22100%22%7D
	@Test
	public void givenRequestForDiscovery_whenSearchTargetPlmnListIsValid_theReturnJsonStructure() throws Exception{

		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		HashMap<String,Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.setPlmnList(null);
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.setPlmnList(Arrays.asList(new Plmn("310","14"),new Plmn("450","05") ));
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&target-plmn-list=%7B%22mcc%22%3A%22310%22%2C%22mnc%22%3A%2214%22%7D%2C%7B%22mcc%22%3A%22301%22%2C%22mnc%22%3A%22100%22%7D");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();

		SearchResult retObj = om.readValue(jsonStr, new TypeReference<SearchResult>() {});
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
	}
	
	// given - discovery request
	// when -  target-plmn-list is valid, and plmnList of Nf are absent hence nrf plmnList is used 
	// then - nfProfiles matching those target-plmn-list
	// with - target-plmn-list=%5B%7B%22mcc%22%3A%22310%22%2C%22mnc%22%3A%2214%22%7D%2C%7B%22mcc%22%3A%22301%22%2C%22mnc%22%3A%22100%22%7D%5D
	@Test
	public void givenRequestForDiscovery_whenSearchTargetPlmnListIsCorrect_theReturnJsonStructure() throws Exception{

		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.setPlmnList(null);
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.setPlmnList(Arrays.asList(new Plmn("310","14"),new Plmn("450","05") ));
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&target-plmn-list=%5B%7B%22mcc%22%3A%22310%22%2C%22mnc%22%3A%2214%22%7D%2C%7B%22mcc%22%3A%22301%22%2C%22mnc%22%3A%22100%22%7D%5D");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();

		SearchResult retObj = om.readValue(jsonStr, new TypeReference<SearchResult>() {});
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
	}
	
	// given - discovery request
	// when -  target-plmn-list is valid, and plmnList of Nf are absent hence nrf plmnList is used 
	// then - nfProfiles matching those target-plmn-list
	// with - target-plmn-list=%7B%22mcc%22%3A%22310%22%2C%22mnc%22%3A%2214%22%7D&target-plmn-list=%7B%22mcc%22%3A%22301%22%2C%22mnc%22%3A%22100%22%7D
	@Test
	public void givenRequestForDiscovery_whenSearchTargetPlmnListCorrect_theReturnJsonStructure() throws Exception{

		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.setPlmnList(null);
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.setPlmnList(Arrays.asList(new Plmn("310","14"),new Plmn("450","05") ));
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&target-plmn-list=%7B%22mcc%22%3A%22310%22%2C%22mnc%22%3A%2214%22%7D&target-plmn-list=%7B%22mcc%22%3A%22301%22%2C%22mnc%22%3A%22100%22%7D");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();

		SearchResult retObj = om.readValue(jsonStr, new TypeReference<SearchResult>() {});
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
	}
	
	// given - discovery request
	// when -  target-plmn-list is valid, and plmnList of Nf are absent hence nrf plmnList is used 
	// then - nfProfiles matching those target-plmn-list
	// with - target-plmn-list={\"mcc\":\"310\",\"mnc\":\"14\"}&target-plmn-list={\"mcc\":\"301\",\"mnc\":\"100\"}
	@Test
	public void givenRequestForDiscovery_whenSearchTargetPlmnList_theReturnJsonStructure() throws Exception{

		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.setPlmnList(null);
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.setPlmnList(Arrays.asList(new Plmn("310","14"),new Plmn("450","05") ));
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response",nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&target-plmn-list={\"mcc\":\"310\",\"mnc\":\"14\"}&target-plmn-list={\"mcc\":\"301\",\"mnc\":\"100\"}");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();

		SearchResult retObj = om.readValue(jsonStr, new TypeReference<SearchResult>() {});
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
	}

	// given - discovery request
	// when - service-names and preferred-locality are valid
	// then - nfProfiles matching those service-names and locality
	@Test
	public void givenRequestForDiscoveryBypreferredLocality_theReturnJsonStructure() throws Exception{

		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		HashMap<String,Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.getNfServices().get(0).setServiceName("amf-5g-policy-1");
		nfProfile.setLocality("US West");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));

		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.getNfServices().get(1).setServiceName("amf-5g-control-1");
		nfProfile.setLocality("US West");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		SearchResult searchResult = new SearchResult();
		searchResult.setNfInstances(nfProfiles);
		searchResult.setValidityPeriod(300);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&service-names=[\"amf-5g-policy-1\",\"amf-5g-control-1\"]&preferred-locality=\"US West\"");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();

		SearchResult retObj = om.readValue(jsonStr, new TypeReference<SearchResult>() {});
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
	}
	
	@Test
//	 * AMF registered with amfSetId and amfRegionId
//	 * GET Request for profiles with filter condition for amfRegionId amfSetId
	public void testDiscoverWithAmfInfo_amfRegionId() throws UnsupportedEncodingException, Exception {
		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.getNfServices().get(0).setServiceName("amf-service-1");
		nfProfile.getAmfInfo().setAmfRegionId("amf-Region-1");
		nfProfile.getAmfInfo().setAmfSetId("abc123");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));

		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.getNfServices().get(1).setServiceName("amf-service-2");
		nfProfile.getAmfInfo().setAmfRegionId("amf-Region-1");
		nfProfile.getAmfInfo().setAmfSetId("abc123");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		ObjectMapper om = new ObjectMapper();
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&amf-region-Id=amf-Region-1&amf-set-Id=abc123");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();
		
		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();

		SearchResult  retObj = om.readValue(jsonStr, new TypeReference<SearchResult>() {});
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
		     
	}
	
	@Test
	public void givenRequestForDiscovery_validateMaxAgeInResponseHeader() throws Exception{

		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.getNfServices().get(0).setServiceName("namf-mt");
		
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.getNfServices().get(1).setServiceName("namf-evts");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&service-names=namf-mt,namf-evts");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();
	
		SearchResult retObj = om.readValue(jsonStr, new TypeReference<SearchResult>() {});
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
		
		String respCacheControl = respObj.getHeader("Cache-Control");
		CacheControl expectedCacheControl = CacheControl.maxAge((long)this.validityPeriodSecs.getSeconds(), TimeUnit.SECONDS);
		Assert.assertEquals(expectedCacheControl.getHeaderValue(),respCacheControl);

	}
	
	@Test
	public void testForComplexQueryRequest() throws Exception {
		Counter s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "PCF").tag("TargetNfType","AMF").counter();
		double prev_requests = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
	               .tag("RequesterNfType", "PCF").tag("TargetNfType","AMF").tag("HttpStatusCode","400").counter();
		double prev_response = (s != null) ? s.count() : 0;
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
                .tag("RequesterNfType", "PCF").counter();
		double prev_perService = (s != null) ? s.count() : 0;
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&complex-query=abc");
                return request;
            }
        })).andExpect(status().isBadRequest())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();
	
		ProblemDetails problemDetails = om.readValue(jsonStr, new TypeReference<ProblemDetails>() {});
		Assert.assertEquals(problemDetails.getTitle(), "Bad Request");
		Assert.assertEquals(problemDetails.getDetail(), "Invalid input data");
		Assert.assertEquals(problemDetails.getCause(), "INVALID_QUERY_PARAM");
		Assert.assertEquals(problemDetails.getInvalidParams().get(0).getParam(), "complex-query");
		Assert.assertEquals(problemDetails.getInvalidParams().get(0).getReason(), "'complex-query' is an invalid Query Parameter");
		
	    // Updated metrics
	    Assert.assertEquals(prev_requests+1,Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "PCF").tag("TargetNfType","AMF").counter().count(),0);
	    Assert.assertEquals(prev_response+1, Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
				               .tag("RequesterNfType", "PCF").tag("TargetNfType","AMF").tag("HttpStatusCode","400").counter().count(),0);
	    
	    s= Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
                .tag("RequesterNfType", "PCF").counter();
		double current = (s != null) ? s.count() : 0;
		Assert.assertEquals(prev_perService, current,0);
	}
	
	@Test
	public void testRequiredFeaturesFilter_errorScenarios() throws Exception {
		Counter s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "PCF").tag("TargetNfType","AMF").counter();
		double prev_requests = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
	               .tag("RequesterNfType", "PCF").tag("TargetNfType","AMF").tag("HttpStatusCode","400").counter();
		double prev_response = (s != null) ? s.count() : 0;
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
                .tag("RequesterNfType", "PCF").counter();
		double prev_perService = (s != null) ? s.count() : 0;
		// When the request has required-features but no service-names 
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&required-features=10,800");
                return request;
            }
        })).andExpect(status().isBadRequest())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();
		String jsonStr = respObj.getContentAsString();
	
		ProblemDetails problemDetails = om.readValue(jsonStr, new TypeReference<ProblemDetails>() {});
        Assert.assertEquals(problemDetails.getTitle(), "Bad Request");
        Assert.assertEquals(problemDetails.getDetail(), "Invalid input data");
        Assert.assertEquals(problemDetails.getCause(), "Bad Request");
        Assert.assertEquals(problemDetails.getInvalidParams().get(0).getParam(), "required-features");
        Assert.assertEquals(problemDetails.getInvalidParams().get(0).getReason(), "The size of required-features must be the same as service-names");
        
	    // Updated metrics
	    Assert.assertEquals(prev_requests+1,Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests").tag("RequesterNfType", "PCF").tag("TargetNfType","AMF").counter().count(),0);
	    Assert.assertEquals(prev_response+1, Metrics.globalRegistry.find("ocnrf.nfDiscover.tx.responses")
				               .tag("RequesterNfType", "PCF").tag("TargetNfType","AMF").tag("HttpStatusCode","400").counter().count(),0);
	    
	    s= Metrics.globalRegistry.find("ocnrf.nfDiscover.rx.requests.success.perService")
                .tag("RequesterNfType", "PCF").counter();
		double current = (s != null) ? s.count() : 0;
		Assert.assertEquals(prev_perService, current,0);
        
        // When the size of required-features doesn't match with the size of service-names 
 		res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&service-names=namf-mt&required-features=10,800");
                return request;
            }
        })).andExpect(status().isBadRequest())
 				.andReturn();

 		respObj = res.getResponse();
 		jsonStr = respObj.getContentAsString();
 	
 		 problemDetails = om.readValue(jsonStr, new TypeReference<ProblemDetails>() {});
         Assert.assertEquals(problemDetails.getTitle(), "Bad Request");
         Assert.assertEquals(problemDetails.getDetail(), "Invalid input data");
         Assert.assertEquals(problemDetails.getCause(), "Bad Request");
         Assert.assertEquals(problemDetails.getInvalidParams().get(0).getParam(), "required-features");
         Assert.assertEquals(problemDetails.getInvalidParams().get(0).getReason(), "The size of required-features must be the same as service-names");
         
         // When the required-features contains elements of invalid type (i.e. non-hexadecimal strings)
         res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
             public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                 request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF&service-names=namf-mt,nudm-sdm&required-features=AA100,HAL8");
                 return request;
             }
         })).andExpect(status().isBadRequest())
  				.andReturn();

  		respObj = res.getResponse();
  		jsonStr = respObj.getContentAsString();
  	
  		 problemDetails = om.readValue(jsonStr, new TypeReference<ProblemDetails>() {});
          Assert.assertEquals(problemDetails.getTitle(), "Bad Request");
          Assert.assertEquals(problemDetails.getDetail(), "Invalid input data");
          Assert.assertEquals(problemDetails.getCause(), "Bad Request");
          Assert.assertEquals(problemDetails.getInvalidParams().get(0).getParam(), "requiredFeatures[1].<list element>");
          Assert.assertEquals(problemDetails.getInvalidParams().get(0).getReason(), "'requiredFeatures' should be a valid value");
	}
	
	@Test
	public void givenRequestForDiscovery_NotFound_PegOcnrfNfdiscoverProfilesDiscoveredCount_Bucket0() throws Exception{
		Counter s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","1").counter();
		double count_bucket_1 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","2").counter();
		double count_bucket_2 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","3").counter();
		double count_bucket_3 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","4").counter();
		double count_bucket_4 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","5").counter();
		double count_bucket_5 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","6").counter();	
		double count_bucket_6 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","7").counter();
		double count_bucket_7 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","8").counter();	
		double count_bucket_8 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","9").counter();	
		double count_bucket_9 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","10").counter();	
		double count_bucket_10 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","+Inf").counter();
		double count_bucket_Inf = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","0").counter();
		double count_bucket_0 = (s != null) ? s.count() : 0;
		
		ProblemDetails problemDetails = ProblemDetails.forNotFound();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		reHashMap.put("response", problemDetails);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(problemDetails);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();
		SearchResult retObj = om.readValue(jsonStr, SearchResult.class);
		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
		Assert.assertEquals(0, nfProfiles.size());
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","1").counter();
		double count_bucket_1_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","2").counter();
		double count_bucket_2_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","3").counter();
		double count_bucket_3_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","4").counter();
		double count_bucket_4_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","5").counter();
		double count_bucket_5_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","6").counter();
		double count_bucket_6_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","7").counter();
		double count_bucket_7_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","8").counter();
		double count_bucket_8_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","9").counter();
		double count_bucket_9_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","10").counter();
		double count_bucket_10_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","+Inf").counter();
		double count_bucket_Inf_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","0").counter();
		double count_bucket_0_after = (s != null) ? s.count() : 0;
		
		Assert.assertEquals(count_bucket_1, count_bucket_1_after,0);
		Assert.assertEquals(count_bucket_2, count_bucket_2_after,0);
		Assert.assertEquals(count_bucket_3, count_bucket_3_after,0);
		Assert.assertEquals(count_bucket_4, count_bucket_4_after,0);
		Assert.assertEquals(count_bucket_5, count_bucket_5_after,0);
		Assert.assertEquals(count_bucket_6, count_bucket_6_after,0);
		Assert.assertEquals(count_bucket_7, count_bucket_7_after,0);
		Assert.assertEquals(count_bucket_8, count_bucket_8_after,0);
		Assert.assertEquals(count_bucket_9, count_bucket_9_after,0);
		Assert.assertEquals(count_bucket_10, count_bucket_10_after,0);
		Assert.assertEquals(count_bucket_Inf, count_bucket_Inf_after,0);	
		Assert.assertEquals(count_bucket_0+1, count_bucket_0_after,0);	

	}
	
	@Test
	public void givenRequestForDiscovery_ErrorOccurs_NotPegOcnrfNfdiscoverProfilesDiscoveredCount() throws Exception{

		Counter s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","1").counter();
		double count_bucket_1 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","2").counter();
		double count_bucket_2 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","3").counter();
		double count_bucket_3 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","4").counter();
		double count_bucket_4 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","5").counter();
		double count_bucket_5 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","6").counter();	
		double count_bucket_6 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","7").counter();
		double count_bucket_7 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","8").counter();	
		double count_bucket_8 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","9").counter();	
		double count_bucket_9 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","10").counter();	
		double count_bucket_10 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","+Inf").counter();
		double count_bucket_Inf = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","0").counter();	
		double count_bucket_0 = (s != null) ? s.count() : 0;
		
		ProblemDetails prob = ProblemDetails.forBadRequest();
		prob.setDetail("Invalid input data");
		prob.addInvalidParam(new InvalidParam("targetNfType","must not be null"));
		
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("Target-nf-type=PCF&requester-nf-type=AMF");
                return request;
            }
        })).andExpect(status().isBadRequest())
        		.andReturn();
		
		MockHttpServletResponse respObj = res.getResponse();
		
		String jsonStr = respObj.getContentAsString();

		ProblemDetails retObj = om.readValue(jsonStr, ProblemDetails.class);
		Assert.assertEquals(prob, retObj);
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","1").counter();
		double count_bucket_1_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","2").counter();
		double count_bucket_2_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","3").counter();
		double count_bucket_3_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","4").counter();
		double count_bucket_4_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","5").counter();
		double count_bucket_5_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","6").counter();
		double count_bucket_6_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","7").counter();
		double count_bucket_7_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","8").counter();
		double count_bucket_8_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","9").counter();
		double count_bucket_9_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","10").counter();
		double count_bucket_10_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","+Inf").counter();
		double count_bucket_Inf_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","0").counter();
		double count_bucket_0_after = (s != null) ? s.count() : 0;
		
		Assert.assertEquals(count_bucket_1, count_bucket_1_after,0);
		Assert.assertEquals(count_bucket_2, count_bucket_2_after,0);
		Assert.assertEquals(count_bucket_3, count_bucket_3_after,0);
		Assert.assertEquals(count_bucket_4, count_bucket_4_after,0);
		Assert.assertEquals(count_bucket_5, count_bucket_5_after,0);
		Assert.assertEquals(count_bucket_6, count_bucket_6_after,0);
		Assert.assertEquals(count_bucket_7, count_bucket_7_after,0);
		Assert.assertEquals(count_bucket_8, count_bucket_8_after,0);
		Assert.assertEquals(count_bucket_9, count_bucket_9_after,0);
		Assert.assertEquals(count_bucket_10, count_bucket_10_after,0);
		Assert.assertEquals(count_bucket_Inf, count_bucket_Inf_after,0);	
		Assert.assertEquals(count_bucket_0, count_bucket_0_after,0);
	
	}
	
	@Test
	public void givenRequestForDiscovery_whenTargetNfTypeValid_pegOcnrfNfdiscoverProfilesDiscoveredCount_Bucket2() throws Exception{
		
		Counter s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","1").counter();
		double count_bucket_1 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","2").counter();
		double count_bucket_2 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","3").counter();
		double count_bucket_3 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","4").counter();
		double count_bucket_4 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","5").counter();
		double count_bucket_5 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","6").counter();	
		double count_bucket_6 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","7").counter();
		double count_bucket_7 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","8").counter();	
		double count_bucket_8 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","9").counter();	
		double count_bucket_9 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","10").counter();	
		double count_bucket_10 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","+Inf").counter();
		double count_bucket_Inf = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","0").counter();	
		double count_bucket_0 = (s != null) ? s.count() : 0;
		
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		HashMap<String,Object> reHashMap = new HashMap<String, Object>();
		// return 2 profiles
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));

		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response",nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();
		SearchResult retObj = om.readValue(jsonStr, SearchResult.class);
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
		Assert.assertEquals("2", retObj.getNrfSupportedFeatures());
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","1").counter();
		double count_bucket_1_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","2").counter();
		double count_bucket_2_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","3").counter();
		double count_bucket_3_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","4").counter();
		double count_bucket_4_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","5").counter();
		double count_bucket_5_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","6").counter();
		double count_bucket_6_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","7").counter();
		double count_bucket_7_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","8").counter();
		double count_bucket_8_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","9").counter();
		double count_bucket_9_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","10").counter();
		double count_bucket_10_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","+Inf").counter();
		double count_bucket_Inf_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","0").counter();
		double count_bucket_0_after = (s != null) ? s.count() : 0;
		
		Assert.assertEquals(count_bucket_1, count_bucket_1_after,0);
		Assert.assertEquals(count_bucket_2 + 1, count_bucket_2_after,0);
		Assert.assertEquals(count_bucket_3, count_bucket_3_after,0);
		Assert.assertEquals(count_bucket_4, count_bucket_4_after,0);
		Assert.assertEquals(count_bucket_5, count_bucket_5_after,0);
		Assert.assertEquals(count_bucket_6, count_bucket_6_after,0);
		Assert.assertEquals(count_bucket_7, count_bucket_7_after,0);
		Assert.assertEquals(count_bucket_8, count_bucket_8_after,0);
		Assert.assertEquals(count_bucket_9, count_bucket_9_after,0);
		Assert.assertEquals(count_bucket_10, count_bucket_10_after,0);
		Assert.assertEquals(count_bucket_Inf, count_bucket_Inf_after,0);
		Assert.assertEquals(count_bucket_0, count_bucket_0_after,0);
	}
	
	@Test
	public void givenRequestForDiscovery_whenTargetNfTypeValid_pegOcnrfNfdiscoverProfilesDiscoveredCount_Bucket6() throws Exception{
		
		Counter s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","1").counter();
		double count_bucket_1 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","2").counter();
		double count_bucket_2 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","3").counter();
		double count_bucket_3 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","4").counter();
		double count_bucket_4 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","5").counter();
		double count_bucket_5 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","6").counter();	
		double count_bucket_6 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","7").counter();
		double count_bucket_7 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","8").counter();	
		double count_bucket_8 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","9").counter();	
		double count_bucket_9 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","10").counter();	
		double count_bucket_10 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","+Inf").counter();
		double count_bucket_Inf = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","0").counter();	
		double count_bucket_0 = (s != null) ? s.count() : 0;
		
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		HashMap<String,Object> reHashMap = new HashMap<String, Object>();
		// return 6 profiles
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));

		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();
		SearchResult retObj = om.readValue(jsonStr, SearchResult.class);
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
		Assert.assertEquals("2", retObj.getNrfSupportedFeatures());
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","1").counter();
		double count_bucket_1_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","2").counter();
		double count_bucket_2_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","3").counter();
		double count_bucket_3_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","4").counter();
		double count_bucket_4_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","5").counter();
		double count_bucket_5_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","6").counter();
		double count_bucket_6_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","7").counter();
		double count_bucket_7_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","8").counter();
		double count_bucket_8_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","9").counter();
		double count_bucket_9_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","10").counter();
		double count_bucket_10_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","+Inf").counter();
		double count_bucket_Inf_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","0").counter();
		double count_bucket_0_after = (s != null) ? s.count() : 0;
		
		Assert.assertEquals(count_bucket_1, count_bucket_1_after,0);
		Assert.assertEquals(count_bucket_2 , count_bucket_2_after,0);
		Assert.assertEquals(count_bucket_3, count_bucket_3_after,0);
		Assert.assertEquals(count_bucket_4, count_bucket_4_after,0);
		Assert.assertEquals(count_bucket_5, count_bucket_5_after,0);
		Assert.assertEquals(count_bucket_6 + 1, count_bucket_6_after,0);
		Assert.assertEquals(count_bucket_7, count_bucket_7_after,0);
		Assert.assertEquals(count_bucket_8, count_bucket_8_after,0);
		Assert.assertEquals(count_bucket_9, count_bucket_9_after,0);
		Assert.assertEquals(count_bucket_10, count_bucket_10_after,0);
		Assert.assertEquals(count_bucket_Inf, count_bucket_Inf_after,0);
		Assert.assertEquals(count_bucket_0, count_bucket_0_after,0);

	}
	
	@Test
	public void givenRequestForDiscovery_whenTargetNfTypeValid_pegOcnrfNfdiscoverProfilesDiscoveredCount_BucketInf() throws Exception{
		
		Counter s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","1").counter();
		double count_bucket_1 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","2").counter();
		double count_bucket_2 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","3").counter();
		double count_bucket_3 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","4").counter();
		double count_bucket_4 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","5").counter();
		double count_bucket_5 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","6").counter();	
		double count_bucket_6 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","7").counter();
		double count_bucket_7 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","8").counter();	
		double count_bucket_8 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","9").counter();	
		double count_bucket_9 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","10").counter();	
		double count_bucket_10 = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","+Inf").counter();
		double count_bucket_Inf = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","0").counter();	
		double count_bucket_0 = (s != null) ? s.count() : 0;
		
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		HashMap<String,Object> reHashMap = new HashMap<String, Object>();
		// return 11 profiles
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));

		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();

		MockHttpServletResponse respObj = res.getResponse();

		String jsonStr = respObj.getContentAsString();
		SearchResult retObj = om.readValue(jsonStr, SearchResult.class);
		Assert.assertEquals(nfProfiles, retObj.getNfInstances());
		Assert.assertEquals("2", retObj.getNrfSupportedFeatures());
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","1").counter();
		double count_bucket_1_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","2").counter();
		double count_bucket_2_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","3").counter();
		double count_bucket_3_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","4").counter();
		double count_bucket_4_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","5").counter();
		double count_bucket_5_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","6").counter();
		double count_bucket_6_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","7").counter();
		double count_bucket_7_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","8").counter();
		double count_bucket_8_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","9").counter();
		double count_bucket_9_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","10").counter();
		double count_bucket_10_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","+Inf").counter();
		double count_bucket_Inf_after = (s != null) ? s.count() : 0;
		
		s = Metrics.globalRegistry.find("ocnrf.nfDiscover.profiles.discovered").tag("TargetNfType","AMF")
				.tag("Bucket","0").counter();
		double count_bucket_0_after = (s != null) ? s.count() : 0;
		
		Assert.assertEquals(count_bucket_1, count_bucket_1_after,0);
		Assert.assertEquals(count_bucket_2 , count_bucket_2_after,0);
		Assert.assertEquals(count_bucket_3, count_bucket_3_after,0);
		Assert.assertEquals(count_bucket_4, count_bucket_4_after,0);
		Assert.assertEquals(count_bucket_5, count_bucket_5_after,0);
		Assert.assertEquals(count_bucket_6 , count_bucket_6_after,0);
		Assert.assertEquals(count_bucket_7, count_bucket_7_after,0);
		Assert.assertEquals(count_bucket_8, count_bucket_8_after,0);
		Assert.assertEquals(count_bucket_9, count_bucket_9_after,0);
		Assert.assertEquals(count_bucket_10, count_bucket_10_after,0);
		Assert.assertEquals(count_bucket_Inf + 1, count_bucket_Inf_after,0);
		Assert.assertEquals(count_bucket_0, count_bucket_0_after,0);

	}

	/*@Test
	public void testReady() throws Exception {
		when(service.getNfProfileForReady(any())).thenReturn(true);
		mvc.perform(get("/nnrf-disc/v1/ready")).andExpect(status().isOk());
		
		when(service.getNfProfileForReady(any())).thenReturn(false);
		mvc.perform(get("/nnrf-disc/v1/ready")).andExpect(status().isNotFound());
	}
	
	@Test
	public void testLive() throws Exception {
		mvc.perform(get("/nnrf-disc/v1/live")).andExpect(status().isOk());
	}*/
	
	@Test
	public void givenRequestForDiscovery_whenNullViaHeaderSent_theReturnHashMap() throws Exception{
		MockHttpServletRequest request = new MockHttpServletRequest();
        request.setQueryString("target-nf-type=PCF&requester-nf-type=PCF");

        // when viaHeader is null
        NFDiscoveryController nFDiscoveryController = new NFDiscoveryController(request);
        ForwardingData forwardingData = nFDiscoveryController.parseViaHeader(request, null);
        Assert.assertEquals(false, forwardingData.isLoop());
        Assert.assertEquals(false, forwardingData.isForwarded());
	}
	
	@Test
	public void givenRequestForDiscovery_whenViaHeaderSent_theReturnLoopDetetctionError() throws Exception{
		Counter s = Metrics.globalRegistry.find("ocnrf.forward.nfDiscover.tx.requests").tag("TargetNfType", "AMF").tag("RequesterNfType","PCF").counter();
		double prev_requests = (s != null) ? s.count() : 0;
		Counter t = Metrics.globalRegistry.find("ocnrf.forward.nfDiscover.rx.responses").tag("TargetNfType", "AMF").tag("RequesterNfType","PCF").tag("HttpStatusCode","508").tag("RejectionReason", "LoopDetected").counter();
		double prev_responses = (t != null) ? t.count() : 0;
		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.getNfServices().get(0).setServiceName("namf-mt");
		
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.getNfServices().get(1).setServiceName("namf-evts");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF");
                request.addHeader("Via", "HTTPS/2.0 ocnrf-ingressgateway.ocnrf.svc.cluster.local:80");
                return request;
            }
        })).andExpect(status().is(508))
				.andReturn();
		        
		verify(mockAppender,atLeastOnce()).append((LogEvent)captorLoggingEvent.capture());
		List<LogEvent> loggingEvent = captorLoggingEvent.getAllValues();
		List<String> logs = new ArrayList<String>();
		for(LogEvent logEvt:loggingEvent) {
			logs.add(logEvt.getMessage().getFormattedMessage());
		}
		//Assert.assertTrue(logs.get(6).contains("logMsg=Via header received, protocolName=HTTPS, protocolVersion=2.0, host=ocnrf-nfDiscovery, port=8080"));
		//Assert.assertTrue(logs.get(10).contains("logMsg=NF discovery failed with errorCondition :NRF_Forwarding_Loop_Detection, problemDetails={\"title\":\"Loop Detected\",\"status\":\"LOOP_DETECTED\",\"detail\":\"Loop Detected\",\"cause\":\"Loop Detected\""));
		s = Metrics.globalRegistry.find("ocnrf.forward.nfDiscover.tx.requests").tag("TargetNfType", "AMF").tag("RequesterNfType","PCF").counter();
		double prev_response = (s != null) ? s.count() : 0;
		t = Metrics.globalRegistry.find("ocnrf.forward.nfDiscover.rx.responses").tag("TargetNfType", "AMF").tag("RequesterNfType","PCF").tag("HttpStatusCode","508").tag("RejectionReason", "LoopDetected").counter();
		double after_responses = (t != null) ? t.count() : 0;
		Assert.assertEquals(prev_response, 1,0.05);
		Assert.assertEquals(after_responses, 1,0.05);
        

	}
	
	@Test
	public void givenRequestForDiscovery_whenViaHeaderSent_thenForwardRequest() throws Exception{
		
		List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
		List<NfInstance> nfInstances = new ArrayList<NfInstance>();
		HashMap<String, Object> reHashMap = new HashMap<String, Object>();
		NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.getNfServices().get(0).setServiceName("namf-mt");
		
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		
		nfProfile = TestDataGenerator.generateNF("AMF");
		nfProfile.getNfServices().get(1).setServiceName("namf-evts");
		nfProfiles.add(nfProfile);
		nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
		reHashMap.put("response", nfProfiles);
		reHashMap.put("profileSearched", true);
		when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
		when(service.discoverNfProfiles(any(),any())).thenReturn(reHashMap);
		when(service.limitNfProfilesInResp(any(),any())).thenReturn(nfProfiles);
		MvcResult res = mvc.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
            public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
                request.setQueryString("target-nf-type=AMF&requester-nf-type=PCF");
                request.addHeader("Via", "HTTPS/2.0 oracle.com:8090");
                return request;
            }
        })).andExpect(status().isOk())
				.andReturn();
		     
		verify(mockAppender,atLeastOnce()).append((LogEvent)captorLoggingEvent.capture());
		List<LogEvent> loggingEvent = captorLoggingEvent.getAllValues();
		List<String> logs = new ArrayList<String>();
		for(LogEvent logEvt:loggingEvent) {
			logs.add(logEvt.getMessage().getFormattedMessage());
		}
		//Assert.assertTrue(logs.get(6).contains("logMsg=Via header received, protocolName=HTTPS, protocolVersion=2.0, host=oracle.com, port=8090"));
		//Assert.assertTrue(logs.get(7).contains("logMsg=forwardedRequest received, nrfHostConfigHostName=oracle.com, nrfHostConfigPort=8090"));

	}
	
	
	@Test
	public void nfDiscover_nfAuthenticationFailureWithoutHeaders() throws Exception {
		NrfSystemOptions nrfSystemOptions = TestDataGenerator.generateNrfSystemOptions();
		NrfEngSystemOptions nrfEngSystemOptions = TestDataGenerator.generateNrfEngSystemOptions();
		nrfSystemOptions.getNfAuthenticationSystemOptions().setNfDiscoveryAuthenticationStatus(FeatureStatus.ENABLED);
		when(nrfSystemOptionsManager.getNrfSystemOptions()).thenReturn(nrfSystemOptions);
		MockHttpServletRequest request = new MockHttpServletRequest();
		validationHelper.setValidationParameters(new ForwardingData(), request, nrfSystemOptions, nrfEngSystemOptions);
		GenericResponse genericResponse = new GenericResponse();
		genericResponse.setResponse(ProblemDetails.forInternalError());
		genericResponse.setHeaders(new HttpHeaders());
		when(validationHelper.performNfAuthentication(any(),any())).thenReturn(genericResponse);
		MvcResult res = mvc
				.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
					public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
						request.setQueryString("target-nf-type=PCF&requester-nf-type=AMF");
						return request;
					}
				})).andExpect(status().is(500)).andReturn();

		MockHttpServletResponse respObj = res.getResponse();
		String jsonStr = respObj.getContentAsString();
		ProblemDetails prob = om.readValue(jsonStr, ProblemDetails.class);
		Assert.assertTrue(prob instanceof ProblemDetails);

	    }
	/*
	@Test
	public void nfDiscover_nfAuthenticationFailureWithHeaders() throws Exception {
		NrfSystemOptions nrfSystemOptions = TestDataGenerator.generateNrfSystemOptions();
		NrfEngSystemOptions nrfEngSystemOptions = TestDataGenerator.generateNrfEngSystemOptions();
		nrfSystemOptions.getNfAuthenticationSystemOptions().setNfDiscoveryAuthenticationStatus(FeatureStatus.ENABLED);
		when(nrfSystemOptionsManager.getNrfSystemOptions()).thenReturn(nrfSystemOptions);
		MockHttpServletRequest request = new MockHttpServletRequest();
		validationHelper.setValidationParameters(new ForwardingData(), request, nrfSystemOptions, nrfEngSystemOptions);
		GenericResponse genericResponse = new GenericResponse();
		genericResponse.setResponse(ProblemDetails.forBadRequest());
		HttpHeaders httpHeaders = new HttpHeaders();
		httpHeaders.add(HttpHeaders.RETRY_AFTER, String.valueOf(2));
		genericResponse.setHeaders(httpHeaders);
		when(validationHelper.performNfAuthentication(any(),any())).thenReturn(genericResponse);
		MvcResult res = mvc
				.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
					public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
						request.setQueryString("target-nf-type=PCF&requester-nf-type=AMF");
						return request;
					}
				})).andExpect(status().isBadRequest()).andReturn();

		MockHttpServletResponse respObj = res.getResponse();
		String jsonStr = respObj.getContentAsString();
		ProblemDetails prob = om.readValue(jsonStr, ProblemDetails.class);
		Assert.assertTrue(prob instanceof ProblemDetails);

	    }*/
	
	
		@Test
		public void nfDiscover_nfAuthenticationSuccess() throws Exception {
			NrfSystemOptions nrfSystemOptions = TestDataGenerator.generateNrfSystemOptions();
			NrfEngSystemOptions nrfEngSystemOptions = TestDataGenerator.generateNrfEngSystemOptions();
			nrfSystemOptions.getNfAuthenticationSystemOptions()
					.setNfDiscoveryAuthenticationStatus(FeatureStatus.ENABLED);
			when(nrfSystemOptionsManager.getNrfSystemOptions()).thenReturn(nrfSystemOptions);
			MockHttpServletRequest request = new MockHttpServletRequest();
			validationHelper.setValidationParameters(new ForwardingData(), request, nrfSystemOptions,
					nrfEngSystemOptions);
			GenericResponse genericResponse = new GenericResponse();
			genericResponse.setResponse(null);
			HttpHeaders httpHeaders = new HttpHeaders();
			httpHeaders.add(HttpHeaders.RETRY_AFTER, String.valueOf(2));
			genericResponse.setHeaders(httpHeaders);
			when(validationHelper.performNfAuthentication(any(),any())).thenReturn(genericResponse);
			List<NfProfile> nfProfiles = new ArrayList<NfProfile>();
			List<NfInstance> nfInstances = new ArrayList<NfInstance>();
			HashMap<String, Object> reHashMap = new HashMap<String, Object>();
			NfProfile nfProfile = TestDataGenerator.generateNF("AMF");
			nfProfile.getNfServices().get(0).setServiceName("namf-mt");
			nfProfiles.add(nfProfile);
			nfInstances.add(new NfInstance(nfProfile, nrfConfig.getGlobalConfig().getNrfInstanceId()));
			reHashMap.put("response", nfProfiles);
			reHashMap.put("profileSearched", true);
			when(service.getNfsBasedOnNfProfileAttributes(any())).thenReturn(nfInstances);
			when(service.discoverNfProfiles(any(), any())).thenReturn(reHashMap);
			when(service.limitNfProfilesInResp(any(), any())).thenReturn(nfProfiles);
			MvcResult res = mvc
					.perform(get("/nnrf-disc/v1/nf-instances").with((RequestPostProcessor) new RequestPostProcessor() {
						public MockHttpServletRequest postProcessRequest(MockHttpServletRequest request) {
							request.setQueryString("target-nf-type=PCF&requester-nf-type=AMF");
							return request;
						}
					})).andExpect(status().isOk()).andReturn();

			MockHttpServletResponse respObj = res.getResponse();
			String jsonStr = respObj.getContentAsString();
			SearchResult retObj = om.readValue(jsonStr, SearchResult.class);
			Assert.assertTrue(retObj instanceof SearchResult);
			Assert.assertEquals(nfProfiles, retObj.getNfInstances());
		}

}
