package com.community.config;

import com.community.domain.enums.SocialType;
import com.community.oauth.ClientResources;
import com.community.oauth.UserTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.filter.OAuth2ClientAuthenticationProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.web.filter.CharacterEncodingFilter;
import org.springframework.web.filter.CompositeFilter;

import javax.servlet.Filter;
import java.util.ArrayList;
import java.util.List;

import static com.community.domain.enums.SocialType.*;

// SecurityConfig.java 각 소셜 미디어의 프로퍼티 값을 호출하는 빈을 등록
// 소셜 미디어 리소스 정보는 시큐리티 설정에서 사용하기 때문에 빈으로 등록
// 3개의 소셜 미디어 프로퍼티를 @ConfigurationProperties 어노테이션에 접두사를 사용하여 바인딩.
@Configuration
@EnableWebSecurity // 웹에서 시큐리티 기능을 사용하겠다는 어노테이션 / 스프링 부트에서는 @EnableWebSecurity 를 사용하면 자동 설정이 적용됩니다.
@EnableOAuth2Client // Oauth2 기능을 사용하겠다는 어노테이션
public class SecurityConfig extends WebSecurityConfigurerAdapter {
    // 자동설정 그대로 사용할 수 있지만 요청, 권한, 기타 설정에 대해서는 필수적으로 최적화한 설정이 들가야합니다.
    // 최적화 설정을 위해 WebSecurityConfigurationAdapter 를 상속받고
    // configure(HttpSecurityhttp) 메서드를 오버라이드하여 원하는 형식의 시큐리티 설정을 합니다.

    @Autowired
    private OAuth2ClientContext oAuth2ClientContext;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        CharacterEncodingFilter filter = new CharacterEncodingFilter();
        http
                // authorizeRequests() 인증 메커니즘을 요청한 HttpServletRequest 기반으로 설정합니다.
            .authorizeRequests()
                // anyMatchers() : 요청 패턴을 리스트 형식으로 설정합니다.
                // permitAll() : 설정한 리퀘스트 패턴을 누구나 접근할 수 있도록 허용합니다.
                .antMatchers("/", "/login/**", "/css/**", "/images/**", "/js/**", "/console/**").permitAll()
                // anyRequest() : 설정한 요청 이외의 리퀘스트 요청을 표현합니다.
                // authenticated() : 해당 요청은 인증된 사용자만 할 수 있습니다.
                .anyRequest().authenticated()
            .and()
                // headers() : 응답에 해당하는 header를 설정합니다. 설정하지 않으면 디폴트값으로 설정됩니다.
                // frameOptions().disable() : XframeOptionsHeaderWriter의 최적화 설정을 허용하지 않습니다.
                .headers().frameOptions().disable()
            .and()
                // authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")) :
                // 인증의 진입 지점입니다. 인증 되지 않은 사용자가 허용되지 않은 경로로 리퀘스트를 요청할 경우 '/login'으로 이동됩니다.
                .exceptionHandling()
                .authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
            .and()
                // formLogin().successForwardUrl("/board/list") : 로그인에 성공하면 설정된 경로로 포워딩됩니다.
                .formLogin()
                .successForwardUrl("/board/list")
            .and()
                // logout() : 로그아웃에 대한 설정을 할 수 있습니다.
                .logout()
                // 코드에서는 로그아웃이 수행될 URL(logoutUrl)
                .logoutUrl("/logout")
                // 로그아웃이 성공했을 때 포워딩 될 URL(logoutSuccessUrl)
                .logoutSuccessUrl("/")
                // 로그아웃을 성공했을 때 삭제될 쿠키값(deleteCookies)
                .deleteCookies("JSESSIONID")
                // 설정된 세션의 무효화 (invalidateHttpSession)을 수행하게끔 설정되어 있습니다.
                .invalidateHttpSession(true)
            .and()
                // addFilterBefore(filter, beforeFilter) : 첫 번째 인자보다 먼저 시작될 필터를 등록합니다.
                // addFilterBefore(filter, CsrFilter.class) : 문자 인코딩 필터(filter) 보다 CsrFilter를 먼저 실행하도록 설정합니다.
                .addFilterBefore(filter, CsrfFilter.class)
                .addFilterBefore(oauth2Filter(), BasicAuthenticationFilter.class)
                .csrf().disable();
    }

    // oauth2ClientFilterRegistration (OAuth2ClientContextFilter filter)메서드는
    // Oauth2 클라이언트용 시큐리티 필터인 OAuth2ClientContextFilter를 불러와서 올바른 순서로 필터가 동작하도록 설정합니다.
    @Bean
    public FilterRegistrationBean oauth2ClientFilterRegistration (
            OAuth2ClientContextFilter filter) {
        FilterRegistrationBean registration = new FilterRegistrationBean();
        registration.setFilter(filter);
        registration.setOrder(-100);
        return registration;
    }

    // oauth2FIlter() 메서드는 오버로드하여 두 개가 정의 되어 있습니다.
    // 첫 번째 oauth2Filter() 메소드로는 각 소셜 미디어 타입을 받아 필터 설정을 할 수 있습니다.
    // 똑같은 이름으로 오버로드한 두 번째 oauth2Filter(ClientResources client, String path, SocialType socialType)
    // 메서드는 각 소셜 미디어 필터를 리스트 형식으로 한꺼번에 설정하여 반환합니다
    private Filter oauth2Filter() {
        CompositeFilter filter = new CompositeFilter();
        List<Filter> filters = new ArrayList<>();
        filters.add(oauth2Filter(facebook(), "/login/facebook", FACEBOOK));
        filters.add(oauth2Filter(google(), "/login/google", GOOGLE));
        filters.add(oauth2Filter(kakao(), "/login/kakao", KAKAO));
        filter.setFilters(filters);
        return filter;
    }

    private Filter oauth2Filter(ClientResources client, String path,
                                SocialType socialType) {
        // 인증이 수행될 경로를 넣어 OAuth2 클라이언트용 인증 처리 필터를 생성합니다.
        OAuth2ClientAuthenticationProcessingFilter filter =
                new OAuth2ClientAuthenticationProcessingFilter(path);
        // 권한 서버와의 통신을 위해 OAuth2RestTemplate 을 생성합니다.
        // 이를 생성하기 위해선 client 프로퍼티 정보와 Oauth2ClientContext 가 필요합니다.
        OAuth2RestTemplate template = new OAuth2RestTemplate(client.getClient(), oAuth2ClientContext);
        filter.setRestTemplate(template);
        // User의 권한을 최적화해서 생성하고자 UserInfoTokenServices를 상속받은 UserTokenService를 생성했습니다.
        // OAuth2 AccessToken 검증을 위해 생성한 UserTokenService를 필터의 토큰 서비스로 등록합니다.
        filter.setTokenServices(new UserTokenService(client, socialType));
        // 인증이 성공적으로 이루어지면 필터에 리다이렉트될 URL을 설정합니다.
        filter.setAuthenticationSuccessHandler((request, response, authentication)
                -> response.sendRedirect("/" + socialType.getValue() +
                "/complete"));
        // 인증이 실패하면 필터에 리다이렉트될 URL을 설정합니다.
        filter.setAuthenticationFailureHandler((request, response, exception) ->
                response.sendRedirect("/error"));
        return filter;
    }

    @Bean
    @ConfigurationProperties("facebook")    // facebook 에 대한 리소스 정보를 빈으로 등록
    public ClientResources facebook() {
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("google")      // google 에 대한 리소스 정보를 빈으로 등록
    public ClientResources google() {
        return new ClientResources();
    }

    @Bean
    @ConfigurationProperties("kakao")       // kakao 에 대한 리소스 정보를 빈으로 등록
    public ClientResources kakao() {
        return new ClientResources();
    }
}
