package com.community;

import com.community.domain.Board;
import com.community.domain.User;
import com.community.domain.enums.BoardType;
import com.community.repository.BoardRepository;
import com.community.repository.UserRepository;
import com.community.resolver.UserArgumentResolver;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurerAdapter;

import java.time.LocalDateTime;
import java.util.List;
import java.util.stream.IntStream;

@SpringBootApplication
public class BootWebApplication extends WebMvcConfigurerAdapter {
    // UserArgumentResolver 클래스를 적용하려면 WebMvcConfigurerAdapter 를 상속받아야한다.

    public static void main(String[] args) {
        SpringApplication.run(BootWebApplication.class, args);
    }

    @Autowired
    private UserArgumentResolver userArgumentResolver;

    // WebMvcConfigurerAdapter 의 내부에 구현된 addArgumentResolvers() 메서드를
    // 오버라이드 하여 UserArgumentResolver 를 추가시켰습니다.
    @Override
    public void addArgumentResolvers(List<HandlerMethodArgumentResolver> argumentResolvers) {
        argumentResolvers.add(userArgumentResolver);
    }

    @Bean
    public CommandLineRunner runner(UserRepository userRepository,
                                    BoardRepository boardRepository) {
        return (args) -> {
            User user = userRepository.save(User.builder()
                .name("havi")
                .password("test")
                .email("havi@gmail.com")
                .createdDate(LocalDateTime.now())
                .build());
            IntStream.rangeClosed(1, 200).forEach(index ->
                    boardRepository.save(Board.builder()
                    .title("게시글" + index)
                    .subTitle("순서" + index)
                    .content("콘텐츠")
                    .boardType(BoardType.free)
                    .createdDate(LocalDateTime.now())
                    .updatedDate(LocalDateTime.now())
                    .user(user).build())
                    );
        };
    }
}
