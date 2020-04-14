package com.community.oauth;

import org.springframework.boot.autoconfigure.security.oauth2.resource.ResourceServerProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;

// @ConfigurationProperties 어노테이션을 사용하며,
// 소셜 미디어에 따라 각각의 프로퍼티값을 바인딩할 수 있습니다.
public class ClientResources {

    @NestedConfigurationProperty // 해당 필드가 단일 값이 아닌 중복으로 바인딩 된다고 표시하는 어노테이션
    private AuthorizationCodeResourceDetails client = new AuthorizationCodeResourceDetails();
    // 설정한 각 소셜의 프로퍼티의 값 중 'client' 를 기준으로 하위의 키/값을 매핑해주는 대상 객체입니다.

    @NestedConfigurationProperty
    private ResourceServerProperties resource = new ResourceServerProperties();
    // 원래 Oauth2 리소스값을 매핑하는 데 사용하지만 여기서는 회원 정보를 얻는 userInfoUri 값을 받는 데 사용했습니다.

    public AuthorizationCodeResourceDetails getClient() {
        return client;
    }

    public ResourceServerProperties getResource() {
        return resource;
    }
}