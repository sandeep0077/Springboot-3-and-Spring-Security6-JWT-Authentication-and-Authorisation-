package com.springsecurity.security.config;

import com.springsecurity.security.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.antlr.v4.runtime.misc.NotNull;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


@Component
@RequiredArgsConstructor
public class JwtConfigurationFilter extends OncePerRequestFilter {

    @Autowired
    private final JwtService jwtService;


    // making it final because we want to use our implementation of this interface to get our user from our database
    @Autowired
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NotNull HttpServletRequest request,
            @NotNull HttpServletResponse response,
            @NotNull FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        if(authHeader == null || !authHeader.startsWith("Bearer ")){
            filterChain.doFilter(request,response);
            return;
        }
            jwt = authHeader.substring(7);

            // extract user name email from jwt token to make a connection with database and retrieve the user
            userEmail = jwtService.extractUserName(jwt);

            // if we have user email from JWT token and also the user is not authenticated because if the user is authenticated then we no need to do this part
            if(userEmail != null && SecurityContextHolder.getContext().getAuthentication()== null){
                UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

                // check if the token is valid or not
                if(jwtService.isTokenValid(jwt,userDetails)){
                    // update the security context and send the request to our dispatcher servlet

                    // create an object , this is need by spring and security context holder to update our security context
                    UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities()
                );
                    authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                    // updating the security context
                    SecurityContextHolder.getContext().setAuthentication(authToken);
                }
            }
            filterChain.doFilter(request,response);
            // now we need to combine (bind) all the filters together that we will do in SecurityConfiguration class
    }
}
