package com.prodmasters.springoauth2resource.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class Controller {

    @GetMapping("/user/helloworld")
    public String helloWorldUser(){
        return "hello world user";
    }

    @GetMapping("/public/helloworld")
    public String helloWorldPublic(){
        return "hello world public";
    }

}
