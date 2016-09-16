package com.tremolosecurity.proxy.auth;

import java.io.IOException;
import java.util.HashMap;

import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.logging.log4j.Logger;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.lang.JoseException;

import com.novell.ldap.LDAPException;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.idp.providers.OpenIDConnectIdP;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.auth.util.AuthStep;
import com.tremolosecurity.proxy.auth.util.OpenIDConnectToken;
import com.tremolosecurity.proxy.filter.HttpFilterConfig;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class GenerateOIDCTokens implements AuthMechanism {

	public static final String UNISON_SESSION_OIDC_ID_TOKEN = "unison.k8s.oidc.idtoken";

	static Logger logger = org.apache.logging.log4j.LogManager.getLogger(GenerateOIDCTokens.class.getName());
	
	
	
	

	
	@Override
	public void init(ServletContext ctx, HashMap<String, Attribute> init) {
		
		

	}

	@Override
	public String getFinalURL(HttpServletRequest request, HttpServletResponse response) {
		
		return null;
	}

	@Override
	public void doGet(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		
		
		HttpSession session = ((HttpServletRequest) request).getSession(); 
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		if (holder == null) {
			throw new ServletException("Holder is null");
		}
		
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		AuthController ac = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL));
		
		String idpName = authParams.get("idpName").getValues().get(0);
		String trustName = authParams.get("trustName").getValues().get(0);
		
		OpenIDConnectToken token = new OpenIDConnectToken(idpName,trustName);
		try {
			token.generateToken(request);
		} catch (JoseException | LDAPException | ProvisioningException | MalformedClaimException e) {
			throw new ServletException("Could not generate token",e);
		}
		
		
		request.getSession().setAttribute(GenerateOIDCTokens.UNISON_SESSION_OIDC_ID_TOKEN, token);
		
		
		as.setSuccess(true);
		holder.getConfig().getAuthManager().nextAuth(request, response,session,false);
		

	}

	@Override
	public void doPost(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doPut(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doHead(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doOptions(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

	@Override
	public void doDelete(HttpServletRequest request, HttpServletResponse response, AuthStep as)
			throws IOException, ServletException {
		this.doGet(request, response, as);

	}

}
