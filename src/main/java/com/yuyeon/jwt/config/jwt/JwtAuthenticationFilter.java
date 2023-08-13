package com.yuyeon.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.yuyeon.jwt.config.auth.PrincipalDetails;
import com.yuyeon.jwt.model.User;
import java.io.IOException;
import java.util.Date;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// 스프링 시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음
// /login 요청해서 username, password 전송하면(post)
// UsernamePasswordAuthenticationFilter 해당 필터가 동작을 한다.
// 그런데 loginForm 을 disable 해놔서 동작을 안함
// 따라서 SecurityConfig 에 해당 필터를 등록 해줘야함
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final AuthenticationManager authenticationManager;

    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    @Override
    public Authentication attemptAuthentication(HttpServletRequest request,
            HttpServletResponse response) throws AuthenticationException {
        System.out.println("JwtAuthenticationFilter 로그인 시도중");

        //1. username, password 받아서
        try {
            ObjectMapper om = new ObjectMapper();
            User user = om.readValue(request.getInputStream(), User.class);
            System.out.println("user = " + user);

            UsernamePasswordAuthenticationToken authenticationToken =
                    new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword());

            // PrincipalDetailsService 의 loadUserByUsername() 함수가 실행됨.
            // DB에 있는 username 과 password가 일치한다.
            Authentication authentication = authenticationManager.authenticate(authenticationToken);

            PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
            System.out.println(
                    "로그인완료됨" + principalDetails.getUser().getUsername()); // 로그인이 정상적으로 되었다는 뜻.

            // authentication 객체가 리턴될 때 session 영역에 저장됨. => 로그인이 되었다는 뜻.
            // 리턴의 이유는 권한관리를 security가 대신 해주기 때문에 편하려고 하는거임.

            //굳이 JWT 토큰을 사용하면서 세션을 만들 이유가 없음. 그치만 단지 권한 처리 때문에 session을 넣어준 것임.

            return authentication;

        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        //2. 정상인지 로그인 시도를 해보는 거에요.
        // authenticationManager 로 로그인 시도를 하면! PrincipalDetailsService 가 자동으로 호출됨.

        //3. PrincipalDetails 를 세션에 담고(권한관리를 위하여)

        //4. JWT 토큰 만들어서 응답해주면 됨.
    }

    //attemptAuthentication 실행 후 인증이 정상적으로 되었으면 successfulAuthentication 함수 실행됨.
    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
            HttpServletResponse response, FilterChain chain, Authentication authResult)
            throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨.");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        String jwtToken = JWT.create()
                .withSubject("cos토큰")
                .withExpiresAt(new Date(System.currentTimeMillis() + (60000 * 10)))
                .withClaim("id", principalDetails.getUser().getId())
                .withClaim("username", principalDetails.getUser().getUsername())
                .sign(Algorithm.HMAC512("cos"));

        response.addHeader("Authorization", "Bearer " + jwtToken);
    }
}
