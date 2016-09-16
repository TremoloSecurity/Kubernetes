/*******************************************************************************
 * Copyright 2016 Tremolo Security, Inc.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *******************************************************************************/
package com.tremolosecurity.proxy.auth.util;

import java.net.MalformedURLException;
import java.util.HashMap;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;

import org.joda.time.DateTime;
import org.jose4j.jws.JsonWebSignature;
import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.MalformedClaimException;
import org.jose4j.lang.JoseException;

import com.novell.ldap.LDAPException;
import com.tremolosecurity.config.util.UrlHolder;
import com.tremolosecurity.idp.providers.OpenIDConnectIdP;
import com.tremolosecurity.provisioning.core.ProvisioningException;
import com.tremolosecurity.proxy.auth.AuthController;
import com.tremolosecurity.proxy.auth.RequestHolder;
import com.tremolosecurity.proxy.util.ProxyConstants;
import com.tremolosecurity.saml.Attribute;
import com.tremolosecurity.server.GlobalEntries;

public class OpenIDConnectToken {
	JwtClaims claims;
	JsonWebSignature jws;
	String encodedJSON;
	DateTime expires;
	String trustName;
	String idpName;
	
	public OpenIDConnectToken(String idpName,String trustName) {
		this.idpName = idpName;
		this.trustName = trustName;
	}
	
	public void generateToken(HttpServletRequest request) throws ServletException, MalformedURLException, JoseException, LDAPException, ProvisioningException, MalformedClaimException {
		HttpSession session = ((HttpServletRequest) request).getSession(); 
		UrlHolder holder = (UrlHolder) request.getAttribute(ProxyConstants.AUTOIDM_CFG);
		if (holder == null) {
			throw new ServletException("Holder is null");
		}
		
		RequestHolder reqHolder = ((AuthController) session.getAttribute(ProxyConstants.AUTH_CTL)).getHolder();
		
		HashMap<String,Attribute> authParams = (HashMap<String,Attribute>) session.getAttribute(ProxyConstants.AUTH_MECH_PARAMS);
		
		AuthController ac = ((AuthController) request.getSession().getAttribute(ProxyConstants.AUTH_CTL));
		
		HashMap<String,OpenIDConnectIdP> idps = (HashMap<String, OpenIDConnectIdP>) GlobalEntries.getGlobalEntries().get(OpenIDConnectIdP.UNISON_OPENIDCONNECT_IDPS);
		
		OpenIDConnectIdP idp = idps.get(this.idpName);
		if (idp == null) {
			throw new ServletException("Could not find idp '" + this.idpName + "'");
		}
		
		
		this.claims = idp.generateClaims(ac.getAuthInfo(), holder.getConfig(), trustName, request); 
		this.jws = idp.generateJWS(getClaims());
		this.encodedJSON = this.jws.getCompactSerialization();
		
		
		
		
		this.expires = new DateTime(claims.getExpirationTime().getValueInMillis());
	}
	
	
	
	public JwtClaims getClaims() {
		return claims;
	}
	
	
	public JsonWebSignature getJws() {
		return jws;
	}
	
	public String getEncodedJSON() {
		return encodedJSON;
	}
	
	
	public DateTime getExpires() {
		return expires;
	}
	public String getTrustName() {
		return trustName;
	}
	
	
	public boolean isExpired() {
		return this.expires.isBeforeNow();
	}

	public String getIdpName() {
		return idpName;
	}
	
	
}
