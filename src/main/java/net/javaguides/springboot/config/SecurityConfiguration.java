package net.javaguides.springboot.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import net.javaguides.springboot.service.UserService;

@Configuration
@EnableWebSecurity
public class SecurityConfiguration {

	@Autowired
	private UserService userService;

	@Bean
	public static BCryptPasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder(); // Bean for password encoding
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf().disable() // Disable CSRF protection for simplicity (consider enabling in production)
				.authorizeHttpRequests((authorize) ->
						authorize.requestMatchers("/registration**").permitAll() // Allow registration access
								.requestMatchers("/login").permitAll() // Allow login access
								.requestMatchers("/js/**").permitAll() // Allow access to JavaScript files
								.requestMatchers("/css/**").permitAll() // Allow access to CSS files
								.requestMatchers("/img/**").permitAll() // Allow access to image files
								.anyRequest().authenticated() // Require authentication for all other requests
				)
				.formLogin(form -> form
						.loginPage("/login") // Specify custom login page
						.permitAll() // Allow all users to access the login page
				)
				.logout(logout -> logout
						.logoutRequestMatcher(new AntPathRequestMatcher("/logout")) // Specify logout URL
						.permitAll() // Allow all users to log out
				);
		return http.build(); // Build the security filter chain
	}

	@Autowired
	public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(userService) // Set the user details service for authentication
				.passwordEncoder(passwordEncoder()); // Set the password encoder for encoding passwords
	}
}