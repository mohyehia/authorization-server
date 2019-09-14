package com.mohyehia.authserver.config;

import java.util.LinkedHashMap;
import java.util.Map;

import org.springframework.security.oauth2.common.DefaultOAuth2AccessToken;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

import com.mohyehia.authserver.entities.User;

public class CustomTokenEnhancer extends JwtAccessTokenConverter {
	@Override
	public OAuth2AccessToken enhance(OAuth2AccessToken accessToken, OAuth2Authentication authentication) {
		User user = (User) authentication.getPrincipal();
		
		Map<String, Object> userInfo = new LinkedHashMap<>(accessToken.getAdditionalInformation());
		
		userInfo.put("email", user.getEmail());
		
		DefaultOAuth2AccessToken defaultOAuth2AccessToken = new DefaultOAuth2AccessToken(accessToken);
		defaultOAuth2AccessToken.setAdditionalInformation(userInfo);
		
		return super.enhance(defaultOAuth2AccessToken, authentication);
	}
}
