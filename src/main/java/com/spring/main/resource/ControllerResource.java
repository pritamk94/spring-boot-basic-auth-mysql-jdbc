package com.spring.main.resource;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@RestController
public class ControllerResource {

    @GetMapping("/")
    public String rootPage(Principal principal){

        return "Hello " + principal.getName() + " , Welcome to mysql jdbc template authentication";
    }
}
