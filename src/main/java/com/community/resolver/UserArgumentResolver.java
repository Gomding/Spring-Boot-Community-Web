package com.community.resolver;

import com.community.annotation.SocialUser;
import com.community.domain.User;
import com.community.domain.enums.SocialType;
import com.community.repository.UserRepository;
import org.springframework.core.MethodParameter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

import javax.servlet.http.HttpSession;
import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

import static com.community.domain.enums.SocialType.*;

@Component
public class UserArgumentResolver implements HandlerMethodArgumentResolver {

    private UserRepository userRepository;

    public UserArgumentResolver(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    // supportParameter() 메서드 : HandlerMethodArgumentResolver 가 해당하는 파라미터를 지원할지 여부를 반환합니다.
    // true 를 반환하면 resolveArgument 메서드가 수행됩니다.
    public boolean supportsParameter(MethodParameter parameter) {
        // supportsParameter() 메서드에 해당하는 어노테이션 타입이 명시되어 있는지 확인하는 로직 추가
        // MethodParameter 로 해당 파라미터의 정보를 받게 됨
        // 이제 파라미터에 @SocialUser 어노테이션이 있고 타입이 User인 파라미터만 true를 반환하게 된다.
        return parameter.getParameterAnnotation(SocialUser.class) != null &&
                parameter.getParameterType().equals(User.class);
    }

    // resolveArgument() 메서드 : 파라미터의 인잣값에 대한 정보를 바탕으로 실제 객체를 생성하여 해당 파라미터 객체에 바인딩 합니다.
    public Object resolveArgument(MethodParameter parameter,
                                  ModelAndViewContainer mavContainer, NativeWebRequest webRequest,
                                  WebDataBinderFactory binderFactory) throws Exception {
                                  // 세션에서 User 객체를 가져오는 resolveArgument() 메서드 구현
        HttpSession session = ((ServletRequestAttributes) RequestContextHolder.
                currentRequestAttributes()).getRequest().getSession();
        User user = (User) session.getAttribute("user");
        return getUser(user, session);
    };

    // 인증된 소셜 미디어 회원의 정보를 가져와 User 객체 만들기
    // getUser() 메서드는 인증된 User 객체를 만드는 메인 메서드 입니다.
    private  User getUser(User user, HttpSession session) {
        if(user == null) {
            try {
                OAuth2Authentication authentication = (OAuth2Authentication)
                        SecurityContextHolder.getContext().getAuthentication();
                Map<String, String> map = (HashMap<String, String>)
                        authentication.getUserAuthentication().getDetails();
                User convertUser = convertUser(String.valueOf(authentication.
                        getAuthorities().toArray()[0]),map);

                user = userRepository.findByEmail(convertUser.getEmail());
                if (user == null) { user = userRepository.save(convertUser); }

                setRoleIfNotSame (user, authentication, map);
                session.setAttribute("user", user);
            }catch (ClassCastException e) {
                return user;
            }
        }
        return user;
    }

    // convertUser() 메서드는 사용자의 인증된 소셜 미디어 타입에 따라 빌더를 사용하여 User 객체를 만들어 주는 가교 역할을 합니다.
    // 카카오의 경우에는 별도의 메서드를 사용합니다
    private User convertUser (String authority, Map<String, String> map) {
        if (FACEBOOK.isEquals(authority)) return getModernUser(FACEBOOK, map);
        else if (GOOGLE.isEquals(authority)) return getModernUser(GOOGLE, map);
        else if (KAKAO.isEquals(authority)) return getKakaoUser(map);
        return null;
    }

    // getModernUser() 메서드는 페이북이나 구글과 같이 공통되는 명명규칙을 가진 그룹을 User 객체로 매핑해줍니다
    private User getModernUser (SocialType socialType, Map<String, String> map) {
        return User.builder()
                .name(map.get("name"))
                .email(map.get("email"))
                .principal(map.get("id"))
                .socialType(socialType)
                .createdDate(LocalDateTime.now())
                .build();
    }

    // getKakaoUser() 메서드는 (키의 네이밍값이 타 소셜 미디어와 다른) 카카오 회원을 위한 메서드 입니다.
    // getModern() 메서드와 동일하게 User 객체로 매핑해줍니다.
    private User getKakaoUser(Map<String, String> map) {
        HashMap<String, String> propertyMap = (HashMap<String, String>)(Object)
                map.get("properties");
        return User.builder()
                .name(propertyMap.get("nickname"))
                .email(map.get("kaccount_email"))
                .principal(String.valueOf(map.get("id")))
                .socialType(KAKAO)
                .createdDate(LocalDateTime.now())
                .build();
    }

    // setRoleIfNotSame() 메서드는 인증된 authentication 이 권한을 갖고 있는지 체크하는 용도로 쓰입니다
    private void setRoleIfNotSame(User user, OAuth2Authentication authentication,
                                  Map<String, String> map) {
        if (!authentication.getAuthorities().contains(new
                SimpleGrantedAuthority(user.getSocialType().getRoleType()))) {
            // 만약 저장된 User 권한이 없으면 SecurityContextHolder 를 사용하여 해당 소셜 미디어 타입으로 권한을 저장합니다
            SecurityContextHolder.getContext().setAuthentication(new
                    UsernamePasswordAuthenticationToken(map, "N/A",
                    AuthorityUtils.createAuthorityList(user.getSocialType().getRoleType())));
        }
    }

}
