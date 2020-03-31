package com.rob.apigatewayzuul.config;

import org.keycloak.adapters.KeycloakConfigResolver;
import org.keycloak.adapters.KeycloakDeployment;
import org.keycloak.adapters.springboot.KeycloakBaseSpringBootConfiguration;
import org.keycloak.adapters.springboot.KeycloakSpringBootConfigResolver;
import org.keycloak.adapters.springsecurity.KeycloakConfiguration;
import org.keycloak.adapters.springsecurity.authentication.KeycloakAuthenticationProvider;
import org.keycloak.adapters.springsecurity.config.KeycloakWebSecurityConfigurerAdapter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticatedActionsFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakAuthenticationProcessingFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakPreAuthActionsFilter;
import org.keycloak.adapters.springsecurity.filter.KeycloakSecurityContextRequestFilter;
import org.keycloak.adapters.springsecurity.management.HttpSessionManager;
import org.keycloak.representations.adapters.config.AdapterConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.boot.web.servlet.RegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy;
import org.springframework.security.web.authentication.session.SessionAuthenticationStrategy;

import javax.servlet.Filter;

@KeycloakConfiguration
public class SecurityConfig extends KeycloakWebSecurityConfigurerAdapter {

//    @Autowired
//    public void configureGlobal(AuthenticationManagerBuilder auth) {
//        SimpleAuthorityMapper grantedAuthorityMapper = new SimpleAuthorityMapper();
//        grantedAuthorityMapper.setPrefix("ROLE_");
//
//        KeycloakAuthenticationProvider keycloakAuthenticationProvider = keycloakAuthenticationProvider();
//        keycloakAuthenticationProvider.setGrantedAuthoritiesMapper(grantedAuthorityMapper);
//        auth.authenticationProvider(keycloakAuthenticationProvider);
//    }

    @Bean
    @Primary
    public KeycloakConfigResolver keycloakConfigResolver() {
        return new KeycloakSpringBootConfigResolver();
    }


    @Bean
    public KeycloakSecurityContextRequestFilter keycloakSecurityContextRequestFilter() {
        return new KeycloakSecurityContextRequestFilter();
    }

    @Bean
    public GrantedAuthoritiesMapper grantedAuthoritiesMapper() {
        SimpleAuthorityMapper mapper = new SimpleAuthorityMapper();
        mapper.setConvertToUpperCase(true);
        return mapper;
    }

    @Override
    protected KeycloakAuthenticationProvider keycloakAuthenticationProvider() {
        final KeycloakAuthenticationProvider provider = super.keycloakAuthenticationProvider();
        provider.setGrantedAuthoritiesMapper(grantedAuthoritiesMapper());
        return provider;
    }

    /**
     * registers the Keycloakauthenticationprovider in spring context and sets its
     * mapping strategy for roles/authorities (mapping to spring seccurities'
     * default ROLE_... for authorities ).
     *
     * @param auth
     *          SecurityBuilder to build authentications and add details like
     *          authproviders etc.
     * @throws Exception
     */
    @Override
    protected void configure(final AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(keycloakAuthenticationProvider());
    }


    @Bean
    @Override
    protected SessionAuthenticationStrategy sessionAuthenticationStrategy() {
        return new RegisterSessionAuthenticationStrategy(new SessionRegistryImpl());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        super.configure(http);
//        http
//                .authorizeRequests()
//                .antMatchers("/movierating/**").hasAnyRole( "user")
////                .antMatchers("/manager").hasRole("Librarian")
//                .anyRequest().permitAll();
//
        http.cors()
                .and()
                .csrf()
                .disable()
                .sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .sessionAuthenticationStrategy(sessionAuthenticationStrategy())
                .and()
                .authorizeRequests()
                .antMatchers("/movierating/**").hasAnyRole( "user")

                .anyRequest().denyAll();


    }

    @Bean
    public PasswordEncoder getPasswordEncoder() {
        return NoOpPasswordEncoder.getInstance();
    }

    @Bean
    public KeycloakDeployment keycloakDeployment() {
        return new KeycloakDeployment();
    }

    /**
     * Load Keycloak configuration from application.properties or application.yml, rather than keycloak.json.
     */



    /**
     * Spring Boot attempts to eagerly register filter beans with the web
     * application context. Therefore, when running the Keycloak Spring Security
     * adapter in a Spring Boot environment, it may be necessary to add two
     * FilterRegistrationBeans to your security configuration to prevent the
     * Keycloak filters from being registered twice.
     *
     * @param filter
     * @return
     */
    @Bean
    public RegistrationBean keycloakAuthenticationProcessingFilterRegistrationBean(KeycloakAuthenticationProcessingFilter filter) {
        RegistrationBean registrationBean = new FilterRegistrationBean((Filter) filter);
        registrationBean.setEnabled(false);
        return registrationBean;
    }

    /**
     * Spring Boot attempts to eagerly register filter beans with the web
     * application context. Therefore, when running the Keycloak Spring Security
     * adapter in a Spring Boot environment, it may be necessary to add two
     * FilterRegistrationBeans to your security configuration to prevent the
     * Keycloak filters from being registered twice.
     *
     * @param filter
     * @return
     */

    @Bean
    public RegistrationBean keycloakPreAuthActionsFilterRegistrationBean(KeycloakPreAuthActionsFilter filter) {
        RegistrationBean registrationBean = new FilterRegistrationBean(filter);
        registrationBean.setEnabled(false);
        return registrationBean;
    }

    @Bean
    @Override
    protected KeycloakAuthenticatedActionsFilter keycloakAuthenticatedActionsRequestFilter() {
        return super.keycloakAuthenticatedActionsRequestFilter();
    }


    @Bean
    public RegistrationBean keycloakAuthenticatedActionsFilterBean(KeycloakAuthenticatedActionsFilter filter) {
        RegistrationBean registrationBean = new FilterRegistrationBean(filter);
        registrationBean.setEnabled(false);
        return registrationBean;
    }

    @Bean
    public RegistrationBean keycloakSecurityContextRequestFilterBean(KeycloakSecurityContextRequestFilter filter) {
        RegistrationBean registrationBean = new FilterRegistrationBean(filter);
        registrationBean.setEnabled(false);
        return registrationBean;
    }


    @Bean
    @Override
    @ConditionalOnMissingBean(HttpSessionManager.class)
    protected HttpSessionManager httpSessionManager() {
        return new HttpSessionManager();
    }

    /**
     * In order to make {@code BookControllerTest} works, the static class {@link CustomKeycloakBaseSpringBootConfiguration}
     * and the annotation {@link EnableConfigurationProperties} were added here.
     * <p>
     * Without them, a NullPointerException will be throw in
     * {@link org.keycloak.adapters.KeycloakDeploymentBuilder#( AdapterConfig )}, because the
     * {@code adapterConfig} parameter is null
     */
    @Configuration
    static class CustomKeycloakBaseSpringBootConfiguration extends KeycloakBaseSpringBootConfiguration {
    }

}
