package com.yuyeon.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {
    @Bean
    public CorsFilter corsFilter(){
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        // 내 서버가 응답을 할 때 json을 자바 스크립트에서 처리할 수 있게 할지를 설정하는 것.
        config.setAllowCredentials(true);
        // 모든 ip 에 응답을 허용하겠다.
        config.addAllowedOrigin("*");
        // 모든 header에 응답을 허용하겠다.
        config.addAllowedHeader("*");
        // 모든 post, get, put, delete, patch 요청을 허용하겠다.
        config.addAllowedMethod("*");
        source.registerCorsConfiguration("/api/**", config);
        return new CorsFilter(source);
    }
}
