package com.tpam.service.gateway.configuration;

import com.tpam.service.gateway.security.JsonWebTokenUtility;
import com.tpam.service.gateway.web.filter.JwtTokenAuthenticationFilter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.servlet.http.HttpServletResponse;

@EnableWebSecurity
public class WebSecurityConfiguration extends WebSecurityConfigurerAdapter {

    private final JsonWebTokenUtility jsonWebTokenUtility;

    public WebSecurityConfiguration(final JsonWebTokenUtility jsonWebTokenUtility) {
        this.jsonWebTokenUtility = jsonWebTokenUtility;
    }

    @Override
    protected void configure(final HttpSecurity http) throws Exception {
        http
            .csrf().disable()
            .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            .and()
            .exceptionHandling().authenticationEntryPoint((req, rsp, e) -> rsp.sendError(HttpServletResponse.SC_UNAUTHORIZED))
            .and()
            .addFilterBefore(new JwtTokenAuthenticationFilter(jsonWebTokenUtility), UsernamePasswordAuthenticationFilter.class)
            .authorizeRequests()
            .antMatchers("/auth/token","/actuator/prometheus").permitAll()
            .anyRequest().authenticated();
    }
}