package com.community.oauth;

import com.community.domain.enums.SocialType;
import org.springframework.boot.autoconfigure.security.oauth2.resource.AuthoritiesExtractor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.UserInfoTokenServices;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

import java.util.List;
import java.util.Map;

// UserInfoTokenServices 를 상속받은 클래스 UserTokenService 를 생성
// UserInfoTokenServices는 스프링 시큐리티 OAuth2에서 제공하는 클래스이며
// User 정보를 얻어오기 위해 소셜 서버와 통신하는 역할을 수행합니다.
// 이때 URI 와 clientId 정보가 필요함
public class UserTokenService extends UserInfoTokenServices {

    // UserInfoTokenServices 생성자에서 super() 를 사용하여 각각의 소셜 미디어 정보를 주입할 수 있도록 합니다.
    public UserTokenService(ClientResources resources, SocialType socialType) {
        super(resources.getResource().getUserInfoUri(), resources.getClient().getClientId());
        setAuthoritiesExtractor(new OAuth2AuthoritiesExtractor(socialType));
        // OAuth2AuthoritiesExtractor 클래스는
        // UserTokenService 의 부모 클래스인 UserInfoTokenService 의 setAuthoritiesExtractor() 메서드를 이용하여 등록합니다.
    }

    // 그리고 AuthritiesExtractor 인터페이스를 구현한 내부 클래스인 Oauth2AuthoritiesExtractor를 생성 했습니다.
    public static class OAuth2AuthoritiesExtractor implements AuthoritiesExtractor {

        private  String socialType;

        // 권한 생성 방식을 "ROLE_FACEBOOK" 으로 하기 위해 SocialType의 getRoleType() 메서드를 사용했습니다.
        public OAuth2AuthoritiesExtractor(SocialType socialType) {
            this.socialType = socialType.getRoleType();
        }


        // extractAuthorities() 메서드를 오버라이드하여 권한을 리스트 형식으로 생성하여 반환하도록 합니다.
        @Override
        public List<GrantedAuthority> extractAuthorities(Map<String, Object> map) {
            return AuthorityUtils.createAuthorityList(this.socialType);
        }
    }
}
