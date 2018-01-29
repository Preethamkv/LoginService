package com.ediscovery.login;
/*
* @author guruprasad on 11/1/18
*/
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class CustomLogoutHandler implements LogoutHandler {
    private static final Logger LOGGER = LoggerFactory.getLogger(CustomLogoutHandler.class);

    @Override
    public void logout(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse,
                       Authentication authentication )
    {

        try
        {
            SecurityContextHolder.getContext().setAuthentication(null);
            SecurityContextHolder.clearContext();
            String responseValue = new ObjectMapper().writeValueAsString("success");
            httpServletResponse.setStatus(HttpServletResponse.SC_ACCEPTED);
            httpServletResponse.addHeader("Content-Type", "application/json");
            httpServletResponse.getWriter().print(responseValue);
        }
        catch( Exception e )
        {
            String responseValue;
            try
            {
                responseValue = new ObjectMapper().writeValueAsString("failed");
                httpServletResponse.setStatus(HttpServletResponse.SC_BAD_REQUEST);
                httpServletResponse.addHeader("Content-Type", "application/json");
                httpServletResponse.getWriter().print(responseValue);
            }
            catch( IOException e1 )
            {
               System.out.println(e1);
            }
        }
    }
}
