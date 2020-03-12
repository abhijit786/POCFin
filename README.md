# Spring Boot custom login logout example

This is just an example of spring boot custom login logout page.

# LDAP Configuration
You can also do authentication using LDAP. For this you need to look at the following [spring security configuration](src/main/java/com/amrut/solution/LdapSecurity.java)

You can add the following lines to your [security configuration adapter](src/main/java/com/amrut/solution/LdapSecurity.java)

         
      // For Ldap authentication configuration
      @Override
      protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
         authenticationManagerBuilder.ldapAuthentication()//
                                 .userSearchFilter("uid={0}")
                                 .contextSource(contextSource());
      }
 
      //For Ldap authentication
      @Bean
      public DefaultSpringSecurityContextSource contextSource() {
      return new DefaultSpringSecurityContextSource(Arrays.asList("ldap://localhost:8080"),
                                         "OU=Employees,O=company,C=Global");
      }
      
    

# Useful intellij plugin

1) [Maven helper plugin](http://plugins.jetbrains.com/plugin/7179-maven-helper):
    This shows the maven dependency tree (As Dependency Analyser option below the pom.xml) as it shows in eclipse. Helps to debug conflicting dependencies in you `pom.xml`
     file
     
     
# Change log

Version 2.0 
--
1) Spring Boot version updated to 2.1.0.RELEASE
2) Now for InMemory Authenticator you need to provide a password encoder. If you still want to use it as plaintext without
encoding use `{noop}` in front of your password to not uses  (NOT recommended to keep password in plain text).
Refer **[spring-security-5-0-0](https://spring.io/blog/2017/11/01/spring-security-5-0-0-rc1-released#password-encoding)**
for more details.
3) Had to exclude ``spring-boot-starter-logging`` for Log4j2 (`spring-boot-starter-log4j2`) to work.
4) Updated `SpringBootServletInitializer` import, as package is changed.

 