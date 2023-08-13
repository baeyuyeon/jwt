package com.yuyeon.jwt.config;

import com.yuyeon.jwt.config.jwt.JwtAuthenticationFilter;
import com.yuyeon.jwt.config.jwt.JwtAuthorizationFilter;
import com.yuyeon.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.web.filter.CorsFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;
    private final UserRepository userRepository;

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //Security 필터가 동작하기 전에 걸어야한다.
        //http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
        http.csrf().disable();

        //세션 사용하지 않겠다.
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(corsFilter) //@CrossOrigin(인증을 안해서 사용안하고), 시큐리티 필터에 인증해야하면 이렇게 등록해서 사용해야함
                .formLogin().disable()
                .httpBasic().disable() // basic 방식 안쓸꺼다.(Bearer 방식 사용할 것이다.)
                .addFilter(new JwtAuthenticationFilter(
                        authenticationManager())) //AuthenticationManager 를 던져줘야함.
                .addFilter(new JwtAuthorizationFilter(
                        authenticationManager(), userRepository)) //AuthenticationManager 를 던져줘야함.
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .anyRequest().permitAll();

    }
}
