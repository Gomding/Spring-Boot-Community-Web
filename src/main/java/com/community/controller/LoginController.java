package com.community.controller;

import com.community.annotation.SocialUser;
import com.community.domain.User;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

// 인증된 User 정보를 세션에 저장해주는 기능 생성
@Controller
public class LoginController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }

    @GetMapping(value = "/{facebook|google|kakao}/conplete")
    public String loginComplete(@SocialUser User user) {
        return "redirect:/board/list";
    }

    /*
    // 인증이 성공적으로 처리된 이후에 리다이렉트되는 경로입니다.
    // 허용하는 요청의 URL 매핑을 /facebook/complete, /google/complete, /kakao/complete 로 제한합니다
    @GetMapping(value = "/{facebook|google|kakao}/conplete")
    public String loginComplete(HttpSession session) {
        // SecurityContextHolder 에서 인증된 정보를 OAuth2Authentication 형태로 받아옵니다
        // OAuth2Authentication 은 기본적인 인증에 대한 정보뿐만 아니라 OAuth2 인증과 관련된 정보도 함께 제공합니다
        OAuth2Authentication authentication = (OAuth2Authentication)
                SecurityContextHolder.getContext().getAuthentication();
        // 리소스 서버에서 받아온 개인정보를 getDetail() 을 사용해 Map 타입으로 받을 수 있습니다.
        Map<String, String> map = (HashMap<String, String>)
           authentication.getUserAuthentication().getDetails();
        session.setAttribute("user", User.builder()
            // 세션에 빌더를 사용하여 인증된 User 정보를 User 객체로 변환하여 저장합니다.
            .name(map.get("name"))
            .email(map.get("email"))
            .principal(map.get("id"))
            .socialType(SocialType.FACEBOOK)
            .createdDate(LocalDateTime.now())
            .build()
        );
        return "redirect:/board/list";
    }*/
}
