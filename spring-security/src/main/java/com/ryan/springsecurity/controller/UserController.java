package com.ryan.springsecurity.controller;

import com.ryan.springsecurity.annotation.IsAdmin;
import com.ryan.springsecurity.annotation.IsUser;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@IsUser
@RestController
@RequestMapping("/user")
public class UserController {

    @RequestMapping("/add")
    public String add() {
        return "user:add";
    }

    @RequestMapping("/update")
    public String update() {
        return "user:update";
    }

    @RequestMapping("/view")
    public String view() {
        return "user:view";
    }

    @RequestMapping("/delete")
    @IsAdmin
    public String delete() {
        return "user:delete";
    }

}