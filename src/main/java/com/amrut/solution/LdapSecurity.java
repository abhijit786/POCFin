package com.amrut.solution;

import java.util.Arrays;

import java.util.Set;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.ldap.DefaultSpringSecurityContextSource;
import org.springframework.security.ldap.userdetails.DefaultLdapAuthoritiesPopulator;
import org.springframework.security.ldap.userdetails.LdapAuthoritiesPopulator;
import org.springframework.security.core.GrantedAuthority;

@Configuration
@EnableWebSecurity
public class LdapSecurity extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
            .authorizeRequests().antMatchers("/css/**").permitAll()
            .and()
            .authorizeRequests().anyRequest().authenticated()
            .and()
            .formLogin()
            .loginPage("/loginPage")
            .loginProcessingUrl("/loginPage").defaultSuccessUrl("/")
            .usernameParameter("username").passwordParameter("password")
            .permitAll()
            .and()
            .logout().logoutSuccessUrl("/loginPage?logout")
            .invalidateHttpSession(true)
            .deleteCookies("JSESSIONID")
            .logoutUrl("/logout")
            .permitAll()
            .and()
            .sessionManagement().sessionFixation().newSession().maximumSessions(1)
            .expiredUrl("/expired");
    }
    



//    @Override
//    protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
//        authenticationManagerBuilder
//                .inMemoryAuthentication()
//                .withUser("prabhu")
//                .password("{noop}prabhu")
//                .authorities("-");
//    }

    // For Ldap authentication configuration
    @Override
    protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
    authenticationManagerBuilder.ldapAuthentication()//
    .userSearchFilter("uid={0}")
    .ldapAuthoritiesPopulator(ldapAuthoritiesPopulator())
    .groupSearchFilter("(member={0})") 
    .contextSource(contextSource());
    }
   
    
    @Bean
    public LdapAuthoritiesPopulator ldapAuthoritiesPopulator() {

    DefaultLdapAuthoritiesPopulator populi = new DefaultLdapAuthoritiesPopulator(contextSource(), "") {

        @Override
        public Set<GrantedAuthority> getGroupMembershipRoles(String userDn, String username) {
            Set<GrantedAuthority> groupMembershipRoles = super.getGroupMembershipRoles(userDn, username);
            System.out.println("Membership Roles "+groupMembershipRoles);

            boolean isMemberOfSpecificAdGroup = false;
            for (GrantedAuthority grantedAuthority : groupMembershipRoles) {
            	System.out.println(grantedAuthority.toString());
                if ("ROLE_MYGROUP".equals(grantedAuthority.toString())) {
                    isMemberOfSpecificAdGroup = true;
                    break;
                }
            }

            if (!isMemberOfSpecificAdGroup) {

                throw new BadCredentialsException("User must be a member of " + "ROLE_MYGROUP");
            }
            return groupMembershipRoles;
        }
    };

        return populi;
    }
    

    // For Ldap authentication
    @Bean
    public DefaultSpringSecurityContextSource contextSource() {
    return new DefaultSpringSecurityContextSource(Arrays.asList("ldap://localhost:10389"), "ou=people,o=sevenSeas,dc=example,dc=com");
    }
}