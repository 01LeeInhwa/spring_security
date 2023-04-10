package shop.mtcoding.securityapp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

    @Bean
    BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        // csrf : 잘못된 경로에서 오는 것을 막아줌
        // 1. CSRF 해제
        http.csrf().disable(); // postman 접근해야 함 - CSR 할때

        // 2. Form 로그인 설정
        http.formLogin()
                .loginPage("/loginForm") // 인증이 안됐을 때 이 페이지로 이동
                .usernameParameter("username")
                .passwordParameter("password")
                .loginProcessingUrl("/login") // POST + X-WWW-Form-urlEncoded가 디폴트
                // .defaultSuccessUrl("/")
                .successHandler((req, resp, authentication) -> {
                    System.out.println("디버그 : 로그인이 완료되었습니다.");
                    resp.sendRedirect("/");
                }) // AOP 안해도 됨, 기록
                .failureHandler((req, resp, ex) -> {
                    System.out.println("디버그 : 로그인이 실패 -> " + ex.getMessage());
                });

        // 3. 인증, 권한 필터 설정
        http.authorizeRequests(
                authroize -> authroize.antMatchers("/users/**").authenticated()
                        .antMatchers("/manager/**")
                        .access("hasRole('ADMIN') or hasRole('MANAGER')")
                        .antMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().permitAll());

        return http.build();
    }
}
